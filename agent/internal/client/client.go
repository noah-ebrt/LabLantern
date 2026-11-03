// Package client spricht den lablantern-Server an. Vertrauen entsteht in zwei Schritten:
//  1. Bootstrap: Das Wurzelzertifikat wird geholt und gegen den Fingerabdruck geprüft, den der Admin
//     aus der Oberfläche mitgebracht hat (nur dieses eine Mal ohne TLS-Prüfung, der Inhalt ist selbstprüfend).
//  2. Danach gilt ausschließlich dieses Zertifikat als Vertrauensanker, mit voller Prüfung inklusive Hostname.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lablantern/agent/internal/collector"
	"lablantern/agent/internal/config"
)

const maxBody = 64 * 1024

type Client struct {
	serverURL  string
	agentToken string
	http       *http.Client
	rejected   bool
}

// Rejected meldet, ob der Master dieses Agent-Token abgelehnt hat (gelöscht oder widerrufen).
func (c *Client) Rejected() bool { return c.rejected }

// FetchAndVerifyCA holt <server>/ca.crt und liefert es nur zurück, wenn sein Fingerabdruck stimmt.
// Es wird dabei kein Geheimnis gesendet.
func FetchAndVerifyCA(serverURL, expectedFingerprint string) ([]byte, error) {
	if expectedFingerprint == "" {
		return nil, fmt.Errorf("CA fingerprint missing: without it the server cannot be trusted")
	}
	caPEM, got, err := FetchCA(serverURL)
	if err != nil {
		return nil, err
	}
	if got != config.NormalizeFingerprint(expectedFingerprint) {
		return nil, fmt.Errorf("server CA fingerprint does NOT match (expected %s, got %s): aborted, nothing was sent",
			config.NormalizeFingerprint(expectedFingerprint), got)
	}
	return caPEM, nil
}

// FetchCA holt das Wurzelzertifikat ohne Vorab-Vertrauen. Ob es das richtige ist, entscheidet beim Pairing
// der Code-Vergleich durch den Admin, der aus genau diesem Fingerabdruck berechnet wird.
func FetchCA(serverURL string) ([]byte, string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, "", fmt.Errorf("server URL must be https://: %q", serverURL)
	}
	hc := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			// Nur für diesen Abruf: Das Zertifikat prüft sich über den Fingerabdruck selbst.
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS12,
		}},
	}
	resp, err := hc.Get(strings.TrimRight(serverURL, "/") + "/ca.crt")
	if err != nil {
		return nil, "", fmt.Errorf("Verbindungsfehler zu %s: %w", serverURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("server did not deliver the root certificate (HTTP %d)", resp.StatusCode)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", fmt.Errorf("server delivered no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return nil, "", fmt.Errorf("delivered file is not a CA")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), config.FingerprintOfDER(cert.Raw), nil
}

// New baut einen Client, der ausschließlich dem übergebenen Wurzelzertifikat vertraut.
func New(serverURL, agentToken string, caPEM []byte) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("root certificate not readable")
	}
	if !strings.HasPrefix(serverURL, "https://") {
		return nil, fmt.Errorf("server URL must be https://")
	}
	return &Client{
		serverURL:  strings.TrimRight(serverURL, "/"),
		agentToken: agentToken,
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}},
		},
	}, nil
}

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	HostType        string `json:"host_type"`
	AgentVersion    string `json:"agent_version"`
}

type EnrollResponse struct {
	OK         bool   `json:"ok"`
	SystemID   int    `json:"system_id"`
	AgentToken string `json:"agent_token"`
	Status     string `json:"status"`
}

func (c *Client) post(path string, body any, bearer string) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, c.serverURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("Verbindungsfehler zu %s: %w", c.serverURL+path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if bearer != "" && (resp.StatusCode == http.StatusUnauthorized ||
		(resp.StatusCode == http.StatusForbidden && strings.Contains(string(out), "revoked"))) {
		c.rejected = true
	}
	return out, resp.StatusCode, nil
}

func (c *Client) Enroll(token, hostname, agentVersion string) (*EnrollResponse, error) {
	out, status, err := c.post("/api/agent/enroll", EnrollRequest{
		EnrollmentToken: token, Hostname: hostname, HostType: "linux", AgentVersion: agentVersion,
	}, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	var res EnrollResponse
	if err := json.Unmarshal(out, &res); err != nil || res.AgentToken == "" {
		return nil, fmt.Errorf("invalid response from server")
	}
	return &res, nil
}

// SendReport liefert die Image-IDs zurück, für die der Server noch keine SBOM hat.
func (c *Client) SendReport(report *collector.HostReport) ([]string, error) {
	out, status, err := c.post("/api/agent/report", report, c.agentToken)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusOK:
		var res struct {
			NeededSBOMs []string `json:"needed_sboms"`
		}
		_ = json.Unmarshal(out, &res)
		return res.NeededSBOMs, nil
	case status == http.StatusForbidden && (strings.Contains(string(out), "waiting for approval") || strings.Contains(string(out), "wartet auf Freigabe")):
		return nil, fmt.Errorf("system is waiting for approval in the LabLantern web UI")
	case status == http.StatusForbidden && (strings.Contains(string(out), "revoked") || strings.Contains(string(out), "widerrufen")):
		return nil, fmt.Errorf("access for this host was revoked in the web UI")
	case status == http.StatusUnauthorized:
		return nil, fmt.Errorf("agent token not accepted (enroll again with 'enroll')")
	}
	return nil, fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
}

// ShouldReport fragt den Server, ob jetzt ein Report fällig ist (stündlich oder auf Anforderung).
func (c *Client) ShouldReport() (bool, error) {
	out, status, err := c.post("/api/agent/poll", map[string]any{}, c.agentToken)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	var res struct {
		Report bool `json:"report"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return false, fmt.Errorf("invalid response from server")
	}
	return res.Report, nil
}

// UploadImageSBOM schickt die SBOM eines Images oder den Grund, warum sie nicht erzeugt werden konnte.
func (c *Client) UploadImageSBOM(imageID string, sbom []byte, errMsg string) error {
	body := map[string]any{"image_id": imageID}
	if errMsg != "" {
		body["error"] = errMsg
	} else {
		body["sbom"] = json.RawMessage(sbom)
	}
	out, status, err := c.post("/api/agent/image-sbom", body, c.agentToken)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	return nil
}

type Command struct {
	ID     int               `json:"id"`
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

type Next struct {
	Report   bool        `json:"report"`
	Commands []Command   `json:"commands"`
	Passkeys *TrustOffer `json:"passkeys"`
}

// TrustOffer ist die aktuelle Passkey-Liste des Masters; übernommen wird sie erst nach Prüfung durch root.
type TrustOffer struct {
	Rev       int    `json:"rev"`
	Envelope  string `json:"envelope"`
	Assertion string `json:"assertion"`
}

// Download lädt eine Datei des Masters (z. B. ein Agent-Paket) nach dest; geprüft wird sie erst von root.
func (c *Client) Download(path, dest string, max int64) error {
	resp, err := c.http.Get(c.serverURL + path)
	if err != nil {
		return fmt.Errorf("download of %s failed: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download of %s failed: HTTP %d", path, resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("download of %s is too large", path)
	}
	return err
}

// NextCommands wartet bis zu wait Sekunden (Long-Poll), ob ein Report fällig ist oder Befehle anliegen.
// Der Agent öffnet dafür keinen Port; die Verbindung geht immer vom Agenten aus.
func (c *Client) NextCommands(wait int) (*Next, error) {
	out, status, err := c.post(fmt.Sprintf("/api/agent/commands/next?wait=%d", wait), map[string]any{}, c.agentToken)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	var n Next
	if err := json.Unmarshal(out, &n); err != nil {
		return nil, fmt.Errorf("invalid response from server")
	}
	return &n, nil
}

func (c *Client) CommandResult(id int, status, output string) error {
	out, code, err := c.post(fmt.Sprintf("/api/agent/commands/%d/result", id),
		map[string]any{"status": status, "output": output}, c.agentToken)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d: %s", code, strings.TrimSpace(string(out)))
	}
	return nil
}

// Pair meldet diesen Host beim Master zum Pairing an. Gesendet wird nur das Commitment (SHA-256 des Geheimnisses);
// der Master antwortet mit seiner Zufallszahl. Das Geheimnis selbst folgt erst danach mit RevealPairing.
func (c *Client) Pair(hostname, commitment, agentVersion string) (int, string, error) {
	out, status, err := c.post("/api/agent/pair", map[string]any{"hostname": hostname, "commitment": commitment,
		"host_type": "linux", "agent_version": agentVersion}, "")
	if err != nil {
		return 0, "", err
	}
	if status != http.StatusOK {
		return 0, "", fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	var res struct {
		PairingID int    `json:"pairing_id"`
		Nonce     string `json:"nonce"`
	}
	if json.Unmarshal(out, &res) != nil || res.PairingID == 0 {
		return 0, "", fmt.Errorf("invalid response from server")
	}
	return res.PairingID, res.Nonce, nil
}

// RevealPairing deckt das Geheimnis auf; erst jetzt kennt der Master den Code, den der Admin vergleicht.
func (c *Client) RevealPairing(id int, secret string) error {
	out, status, err := c.post(fmt.Sprintf("/api/agent/pair/%d/reveal", id), map[string]any{"secret": secret}, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	return nil
}

type PairStatus struct {
	Status     string `json:"status"`
	AgentToken string `json:"agent_token"`
	SystemID   int    `json:"system_id"`
}

func (c *Client) PairingStatus(id int, secret string) (*PairStatus, error) {
	out, status, err := c.post(fmt.Sprintf("/api/agent/pair/%d/status", id), map[string]any{"secret": secret}, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d: %s", status, strings.TrimSpace(string(out)))
	}
	var res PairStatus
	if json.Unmarshal(out, &res) != nil {
		return nil, fmt.Errorf("invalid response from server")
	}
	return &res, nil
}
