package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulnwatch/agent/internal/collector"
	"vulnwatch/agent/internal/config"
)

type pki struct {
	caPEM, caDER []byte
	serverTLS    tls.Certificate
}

// newPKI erzeugt eine CA und ein Serverzertifikat mit IP-SAN 127.0.0.1, wie Caddy es für das LAN ausstellt.
func newPKI(t *testing.T, cn string) pki {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	return pki{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), caDER: caDER,
		serverTLS: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
	}
}

func (p pki) fingerprint() string { return config.FingerprintOfDER(p.caDER) }

func startServer(t *testing.T, p pki, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{p.serverTLS}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func caHandler(p pki, extra http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ca.crt", func(w http.ResponseWriter, r *http.Request) { w.Write(p.caPEM) })
	if extra == nil {
		extra = func(w http.ResponseWriter, r *http.Request) {}
	}
	mux.HandleFunc("/", extra)
	return mux
}

func TestFetchCAAcceptsTheCAWithTheRightFingerprint(t *testing.T) {
	p := newPKI(t, "echte CA")
	s := startServer(t, p, caHandler(p, nil))
	got, err := FetchAndVerifyCA(s.URL, p.fingerprint())
	if err != nil || string(got) != string(p.caPEM) {
		t.Fatalf("err=%v", err)
	}
	// Doppelpunkte und Kleinbuchstaben wie in der Oberfläche dürfen vorkommen
	pretty := strings.ToLower(strings.Join(strings.Split(p.fingerprint(), ""), ""))
	if _, err := FetchAndVerifyCA(s.URL, pretty); err != nil {
		t.Fatal(err)
	}
}

func TestFetchCARefusesAWrongFingerprintAndNamesBothValues(t *testing.T) {
	p := newPKI(t, "echte CA")
	s := startServer(t, p, caHandler(p, nil))
	_, err := FetchAndVerifyCA(s.URL, strings.Repeat("AB", 32))
	if err == nil || !strings.Contains(err.Error(), "NOT") || !strings.Contains(err.Error(), p.fingerprint()) {
		t.Fatalf("erwartet verständliche Ablehnung, erhalten: %v", err)
	}
}

func TestFetchCARequiresAnExpectedFingerprint(t *testing.T) {
	p := newPKI(t, "echte CA")
	s := startServer(t, p, caHandler(p, nil))
	if _, err := FetchAndVerifyCA(s.URL, ""); err == nil {
		t.Fatal("ohne Fingerabdruck darf nichts vertraut werden")
	}
}

func TestFetchCARefusesPlainHTTP(t *testing.T) {
	if _, err := FetchAndVerifyCA("http://127.0.0.1:1", "AA"); err == nil {
		t.Fatal("http:// muss abgelehnt werden")
	}
}

func TestFetchCARefusesNonCAContent(t *testing.T) {
	p := newPKI(t, "echte CA")
	s := startServer(t, p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("kein pem")) }))
	if _, err := FetchAndVerifyCA(s.URL, p.fingerprint()); err == nil {
		t.Fatal("Nicht-PEM muss abgelehnt werden")
	}
}

func TestEnrollSendsTheTokenOnlyAfterVerifiedTLS(t *testing.T) {
	p := newPKI(t, "echte CA")
	var enrolls int32
	s := startServer(t, p, caHandler(p, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/enroll" {
			atomic.AddInt32(&enrolls, 1)
			var req EnrollRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.EnrollmentToken != "einmal" || req.Hostname != "host-a" {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(EnrollResponse{OK: true, SystemID: 7, AgentToken: "geheim", Status: "pending"})
		}
	}))
	caPEM, err := FetchAndVerifyCA(s.URL, p.fingerprint())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(s.URL, "", caPEM)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Enroll("einmal", "host-a", "0.3.0")
	if err != nil || res.AgentToken != "geheim" || res.SystemID != 7 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestClientRefusesAServerSignedByAnotherCA(t *testing.T) {
	real := newPKI(t, "echte CA")
	attacker := newPKI(t, "Angreifer-CA")
	var seen int32
	s := startServer(t, attacker, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&seen, 1) }))
	c, err := New(s.URL, "geheimes-token", real.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enroll("einmal", "host-a", "0.3.0"); err == nil {
		t.Fatal("Zertifikat einer fremden CA muss abgelehnt werden")
	}
	if _, err := c.SendReport(&collector.HostReport{}); err == nil {
		t.Fatal("Report an fremde CA muss scheitern")
	}
	if atomic.LoadInt32(&seen) != 0 {
		t.Fatal("es darf kein Request den Angreifer erreichen (kein Token, keine Daten)")
	}
}

func TestSendReportUsesBearerTokenAndMapsStatuses(t *testing.T) {
	p := newPKI(t, "echte CA")
	status := 200
	body := ""
	var auth string
	s := startServer(t, p, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	c, _ := New(s.URL, "tok123", p.caPEM)
	if _, err := c.SendReport(&collector.HostReport{AgentVersion: "0.3.0"}); err != nil || auth != "Bearer tok123" {
		t.Fatalf("err=%v auth=%q", err, auth)
	}
	cases := []struct {
		status int
		body   string
		want   string
	}{
		{403, `{"detail":"System is waiting for approval by the administrator"}`, "approval"},
		{403, `{"detail":"Agent access for this system was revoked"}`, "revoked"},
		{401, `{"detail":"x"}`, "enroll again"},
		{500, "kaputt", "HTTP 500"},
	}
	for _, tc := range cases {
		status, body = tc.status, tc.body
		_, err := c.SendReport(&collector.HostReport{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d: erwartet %q, erhalten %v", tc.status, tc.want, err)
		}
	}
}

func TestNewRefusesPlainHTTPAndBrokenCA(t *testing.T) {
	p := newPKI(t, "x")
	if _, err := New("http://srv", "t", p.caPEM); err == nil {
		t.Fatal("http muss abgelehnt werden")
	}
	if _, err := New("https://srv", "t", []byte("kein pem")); err == nil {
		t.Fatal("kaputte CA muss abgelehnt werden")
	}
}
