package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"lablantern/agent/internal/actions"
	"lablantern/agent/internal/client"
	"lablantern/agent/internal/collector"
	"lablantern/agent/internal/config"
	"lablantern/agent/internal/discover"
	"lablantern/agent/internal/jobs"
	"lablantern/agent/internal/pairing"
	"lablantern/agent/internal/queries"
)

// AgentVersion wird beim Build per -ldflags überschrieben.
var AgentVersion = "dev"

// Wartezeit auf den Sammler; austauschbar für Tests.
var waitTimeout, waitInterval = 20 * time.Minute, 2 * time.Second

// restartRequested: Der Daemon soll sich beenden, damit der Dienstmanager die neue Version startet (Windows).
var restartRequested bool

func main() {
	if code, ok := serviceMain(); ok {
		os.Exit(code)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, collector.DefaultEnv()))
}

func run(args []string, stdout, stderr io.Writer, env collector.Env) int {
	if len(args) == 0 {
		printHelp(stderr)
		return 2
	}
	switch args[0] {
	case "setup":
		return runSetup(args[1:], stdout, stderr)
	case "enroll":
		return runEnroll(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr, env)
	case "daemon":
		return runDaemon(args[1:], stdout, stderr)
	case "collect-job":
		return runCollectJob(stderr, env, jobs.Default())
	case "action-job":
		return runActionJob(stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "lablantern-agent %s\n", AgentVersion)
		return 0
	case "help", "--help", "-h":
		printHelp(stdout)
		return 0
	}
	if code, ok := platformCLI(args, stdout, stderr); ok {
		return code
	}
	fmt.Fprintf(stderr, "Unknown command %q\n", args[0])
	printHelp(stderr)
	return 2
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, usage, AgentVersion)
}

// Suche und Abfrageintervall; austauschbar für Tests.
var discoverMasters, pairPoll = discover.Masters, 3 * time.Second

// runSetup findet den Master per mDNS (oder --master), holt sein Zertifikat und meldet sich zum Pairing an.
// Erst wenn der Admin den hier angezeigten Code in der Oberfläche bestätigt, gibt es ein Agent-Token.
func runSetup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	master := fs.String("master", "", "master URL, e.g. https://192.0.2.10:8443 (default: search the LAN)")
	hostName := fs.String("hostname", "", "hostname (default: system hostname)")
	configPath := fs.String("config", config.DefaultConfigPath(), "path of the configuration file")
	force := fs.Bool("force", false, "pair again although this host is already set up")
	fp := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the master CA (from the web UI); checked before anything is sent")
	trustPin := fs.String("passkeys-sha256", "", "SHA-256 of the master's passkey list (from the web UI); only that list is trusted first")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !validPin(*trustPin) {
		fmt.Fprintln(stderr, "Error: --passkeys-sha256 must be 64 hex characters.")
		return 2
	}
	if err := requireAdmin(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if _, err := os.Stat(*configPath); err == nil && !*force {
		if code, ok := alreadySetUp(*configPath, stdout, stderr); ok {
			return code
		}
		fmt.Fprintf(stderr, "This host is already set up (%s). Use --force to pair it again.\n", *configPath)
		return 1
	}
	if *hostName == "" {
		h, err := os.Hostname()
		if err != nil {
			h = runtime.GOOS + "-host"
		}
		*hostName = h
	}
	url := strings.TrimRight(*master, "/")
	if url == "" {
		fmt.Fprintln(stdout, "Searching for the LabLantern master on the local network…")
		found, err := discoverMasters(3 * time.Second)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		switch len(found) {
		case 0:
			fmt.Fprintln(stderr, "No master found on this network. Pass it explicitly: sudo lablantern-agent setup --master https://<ip>:8443")
			return 1
		case 1:
			url = found[0]
		default:
			fmt.Fprintf(stderr, "Several masters answered (%s). Choose one with --master.\n", strings.Join(found, ", "))
			return 1
		}
	}
	fmt.Fprintf(stdout, "Master: %s\n", url)
	var caPEM []byte
	var err error
	if *fp != "" {
		// Fingerabdruck aus der Oberfläche: Ein falscher Master fällt hier auf, bevor irgendetwas gesendet wird.
		caPEM, err = client.FetchAndVerifyCA(url, *fp)
		*fp = config.NormalizeFingerprint(*fp)
	} else {
		caPEM, *fp, err = client.FetchCA(url)
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	cl, err := client.New(url, "", caPEM)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	// Erst festlegen (Commitment), dann die Zufallszahl des Masters holen, dann aufdecken: So kann niemand
	// dazwischen ein anderes Geheimnis mit demselben Code für den echten Master suchen.
	secret := pairing.NewSecret()
	id, nonce, err := cl.Pair(*hostName, pairing.Commitment(secret), AgentVersion)
	if err == nil && !pairing.ValidNonce(nonce) {
		err = fmt.Errorf("master sent no valid nonce (is it older than this agent?)")
	}
	if err == nil {
		err = cl.RevealPairing(id, secret)
	}
	if err != nil {
		fmt.Fprintf(stderr, "Pairing request failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "\n    Pairing code:  %s\n\n", pairing.Code(*fp, secret, nonce))
	fmt.Fprintln(stdout, "Open LabLantern → Systems → Pending pairings, check that the code is identical, then approve.")
	fmt.Fprintln(stdout, "A different code means you are not talking to your master: reject it there.")
	fmt.Fprintln(stdout, "Waiting for approval (up to 15 minutes)…")
	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		st, err := cl.PairingStatus(id, secret)
		if err != nil {
			fmt.Fprintf(stderr, "Warning: %v\n", err)
		} else {
			switch st.Status {
			case "approved":
				cfg := &config.Config{ServerURL: url, AgentToken: st.AgentToken, CAFingerprint: *fp, SystemID: st.SystemID,
					PasskeysSHA256: strings.ToLower(*trustPin)}
				if err := config.SaveConfig(*configPath, cfg, caPEM); err != nil {
					fmt.Fprintf(stderr, "Saving the configuration failed: %v\n", err)
					return 1
				}
				fmt.Fprintf(stdout, "✓ Paired as '%s' (system ID %d); master certificate pinned in %s.\n", *hostName, st.SystemID, *configPath)
				msg, err := startDaemon()
				if err != nil {
					fmt.Fprintf(stderr, "Error: %v\n", err)
					return 1
				}
				if msg != "" {
					fmt.Fprintf(stdout, "✓ %s; the first report follows within a minute.\n", msg)
				}
				return 0
			case "pending", "committed":
			default:
				fmt.Fprintf(stderr, "Pairing %s in the LabLantern UI.\n", st.Status)
				return 1
			}
		}
		time.Sleep(pairPoll)
	}
	fmt.Fprintln(stderr, "Not approved within 15 minutes; run setup again.")
	return 1
}

// validPin: leer (keine Vorgabe) oder ein SHA-256 in hex.
func validPin(s string) bool {
	if s == "" {
		return true
	}
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == 64
}

func runEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	serverURL := fs.String("server", "", "server URL, e.g. https://192.0.2.10:8443")
	token := fs.String("token", "", "one-time token from the web UI")
	fp := fs.String("ca-fingerprint", "", "SHA-256 fingerprint of the server CA (from the web UI)")
	configPath := fs.String("config", "", "path of the configuration file")
	hostName := fs.String("hostname", "", "hostname (default: system hostname)")
	trustPin := fs.String("passkeys-sha256", "", "SHA-256 of the master's passkey list (from the web UI); only that list is trusted first")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !validPin(*trustPin) {
		fmt.Fprintln(stderr, "Error: --passkeys-sha256 must be 64 hex characters.")
		return 2
	}
	if err := requireAdmin(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *token == "" && fs.NArg() > 0 {
		*token = fs.Arg(0)
	}
	switch {
	case *serverURL == "" || *token == "":
		fmt.Fprintln(stderr, "Error: --server and --token are required.")
		return 2
	case *fp == "":
		fmt.Fprintln(stderr, "Error: --ca-fingerprint is required. Without it the server cannot be trusted; "+
			"the web UI shows the complete command under Systems.")
		return 2
	}
	if *hostName == "" {
		h, err := os.Hostname()
		if err != nil {
			h = runtime.GOOS + "-host"
		}
		*hostName = h
	}
	target := *configPath
	if target == "" {
		target = config.DefaultConfigPath()
	}

	caPEM, err := client.FetchAndVerifyCA(*serverURL, *fp)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	cl, err := client.New(strings.TrimRight(*serverURL, "/"), "", caPEM)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	res, err := cl.Enroll(*token, *hostName, AgentVersion)
	if err != nil {
		fmt.Fprintf(stderr, "Enrollment failed: %v\n", err)
		return 1
	}
	cfg := &config.Config{
		ServerURL:      strings.TrimRight(*serverURL, "/"),
		AgentToken:     res.AgentToken,
		CAFingerprint:  config.NormalizeFingerprint(*fp),
		SystemID:       res.SystemID,
		PasskeysSHA256: strings.ToLower(*trustPin),
	}
	if err := config.SaveConfig(target, cfg, caPEM); err != nil {
		fmt.Fprintf(stderr, "Saving the configuration failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "✓ Host '%s' enrolled (system ID %d), server CA verified and pinned.\n", *hostName, res.SystemID)
	fmt.Fprintf(stdout, "✓ Configuration: %s\n", target)
	msg, err := startDaemon()
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if msg != "" {
		fmt.Fprintf(stdout, "✓ %s; it reports within a minute.\n", msg)
	}
	fmt.Fprintln(stdout, "Next step: approve the host in the LabLantern web UI under Systems.")
	return 0
}

func runScan(args []string, stdout, stderr io.Writer, env collector.Env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cl, code := loadClient(*configPath, stderr)
	if cl == nil {
		return code
	}
	return deliver(cl, inProcess(env), stdout, stderr)
}

func loadClient(configPath string, stderr io.Writer) (*client.Client, int) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return nil, 1
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return nil, 1
	}
	cl, err := client.New(cfg.ServerURL, cfg.AgentToken, caPEM)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return nil, 1
	}
	return cl, 0
}

type sbomData struct {
	id   string
	data []byte
	err  error
}

// source liefert Report und Image-SBOMs: im Prozess (scan als root) oder über den Sammler (Daemon).
type source struct {
	report func() (*collector.HostReport, error)
	sboms  func(ids []string) ([]sbomData, error)
}

func inProcess(env collector.Env) source {
	return source{
		report: func() (*collector.HostReport, error) { return collector.Collect(env, AgentVersion), nil },
		sboms: func(ids []string) ([]sbomData, error) {
			out := make([]sbomData, 0, len(ids))
			for _, id := range ids {
				data, err := imageSBOM(id)
				out = append(out, sbomData{id, data, err})
			}
			return out, nil
		},
	}
}

func viaCollector(p jobs.Paths) source {
	run := func(ids []string) (*jobs.Result, error) {
		nonce := jobs.NewNonce()
		if err := p.Submit(jobs.Request{Nonce: nonce, SBOMImages: ids}); err != nil {
			return nil, err
		}
		return p.Wait(nonce, waitTimeout, waitInterval)
	}
	return source{
		report: func() (*collector.HostReport, error) {
			res, err := run(nil)
			if err != nil {
				return nil, err
			}
			if res.Report == nil {
				return nil, errors.New("collector returned no report")
			}
			return res.Report, nil
		},
		sboms: func(ids []string) ([]sbomData, error) {
			res, err := run(ids)
			if err != nil {
				return nil, err
			}
			out := make([]sbomData, 0, len(res.SBOMs))
			for _, s := range res.SBOMs {
				d := sbomData{id: s.ImageID}
				if s.Error != "" {
					d.err = errors.New(s.Error)
				} else {
					d.data, d.err = p.ReadSBOM(s)
				}
				out = append(out, d)
			}
			return out, nil
		},
	}
}

func deliver(cl *client.Client, src source, stdout, stderr io.Writer) int {
	report, err := src.report()
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	keys := make([]string, 0, len(report.CollectionErrors))
	for k := range report.CollectionErrors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(stderr, "Warning (%s): %s\n", k, report.CollectionErrors[k])
	}
	needed, err := cl.SendReport(report)
	if err != nil {
		fmt.Fprintf(stderr, "Sending the report failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "✓ Report sent: %d containers, %d packages, %d security updates.\n",
		len(report.Containers), len(report.Packages), report.SecurityUpdatesCount)

	// Nur Images aus dem eigenen Inventar: Der Server kann den Agenten nicht zu beliebigen Images anweisen.
	own := map[string]bool{}
	for _, c := range report.Containers {
		own[c.ImageID] = true
	}
	var ids []string
	for _, id := range needed {
		if own[id] && len(ids) < jobs.MaxSBOMs {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0
	}
	sboms, err := src.sboms(ids)
	if err != nil {
		fmt.Fprintf(stderr, "Warning: image SBOMs not generated: %v\n", err)
		return 0
	}
	for _, s := range sboms {
		msg := ""
		if s.err != nil {
			msg = s.err.Error()
			fmt.Fprintf(stderr, "Warning: SBOM for %s not generated: %v\n", s.id, s.err)
		}
		if err := cl.UploadImageSBOM(s.id, s.data, msg); err != nil {
			fmt.Fprintf(stderr, "Warning: SBOM for %s not uploaded: %v\n", s.id, err)
		} else if s.err == nil {
			fmt.Fprintf(stdout, "✓ Image SBOM uploaded: %s\n", s.id)
		}
	}
	return 0
}

// runDaemon läuft als Benutzer lablantern: hält per Long-Poll eine ausgehende Verbindung zum Master,
// meldet, wenn ein Report fällig ist, und führt Befehle aus der festen Liste aus. Daten erhebt der
// Sammler (root, ohne Netz). Nach dem Start meldet er sofort, damit ein Update gleich sichtbar ist.
func runDaemon(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.SystemConfigPath(), "path of the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	force := true
	watch := pkgWatch{seen: pkgStamp(pkgDBs)}
	for {
		if _, err := os.Stat(*configPath); err != nil {
			time.Sleep(30 * time.Second) // noch nicht eingerichtet
			continue
		}
		if watch.changed(time.Now()) {
			force = true // Pakete installiert, aktualisiert oder entfernt: gleich melden statt erst zur vollen Stunde
		}
		ok := daemonStep(*configPath, jobs.Default(), force, longPollWait, stdout, stderr)
		if restartRequested {
			fmt.Fprintln(stdout, "New version installed; stopping so that the service starts it.")
			return 3
		}
		if ok {
			force = false
		} else if authRejected {
			// gelöscht oder widerrufen: selten nachfragen, bis jemand neu paart oder das Paket entfernt
			fmt.Fprintln(stderr, "The master no longer accepts this agent (deleted or revoked). Retrying in 15 minutes; pair again with 'lablantern-agent setup --force' or remove the package.")
			time.Sleep(rejectedDelay)
		} else {
			time.Sleep(retryDelay)
		}
	}
}

// pkgDBs: Paketdatenbanken von dpkg, rpm, apk und pacman. Ändert sich eine, hat sich der Paketstand geändert.
// pkgSettle: so lange muss sie ruhig sein, bevor gemeldet wird (apt schreibt sie in einem Lauf mehrfach).
var pkgDBs = []string{"/var/lib/dpkg/status", "/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages", "/lib/apk/db/installed", "/var/lib/pacman/local"}
var pkgSettle = 20 * time.Second

// pkgStamp: jüngste Änderungszeit der vorhandenen Paketdatenbanken (Nullzeit, wenn keine da ist).
func pkgStamp(paths []string) time.Time {
	var newest time.Time
	for _, path := range paths {
		if fi, err := os.Stat(path); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}

// pkgWatch merkt sich den Stand beim letzten Blick. Ohne das stünden nach einem Update oder `apt purge` bis zum
// nächsten stündlichen Report noch die alten Pakete und ausstehenden Updates im Master.
type pkgWatch struct {
	paths []string // leer: pkgDBs
	seen  time.Time
}

// changed meldet je Änderung einmal true, sobald die Datenbank pkgSettle lang ruhig ist.
func (w *pkgWatch) changed(now time.Time) bool {
	paths := w.paths
	if paths == nil {
		paths = pkgDBs
	}
	stamp := pkgStamp(paths)
	if stamp.Equal(w.seen) || now.Sub(stamp) < pkgSettle {
		return false
	}
	w.seen = stamp
	return true
}

// Long-Poll-Dauer und Pause nach Fehlern; austauschbar für Tests.
var longPollWait, retryDelay, rejectedDelay = 45, 60 * time.Second, 15 * time.Minute

// authRejected hält fest, ob der letzte Schritt am abgelehnten Token scheiterte.
var authRejected bool

// daemonStep: bei Bedarf ein erzwungener Report, dann ein Long-Poll und was er bringt.
// false heißt: Fehler, der Aufrufer wartet vor dem nächsten Versuch.
func daemonStep(configPath string, p jobs.Paths, force bool, wait int, stdout, stderr io.Writer) bool {
	authRejected = false
	cl, _ := loadClient(configPath, stderr)
	if cl == nil {
		return false
	}
	defer func() { authRejected = cl.Rejected() }()
	if force && deliver(cl, daemonSource(p), stdout, stderr) != 0 {
		return false
	}
	next, err := cl.NextCommands(wait)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return false
	}
	syncPasskeys(next.Passkeys, stdout, stderr)
	reported := false
	if next.Report {
		if deliver(cl, daemonSource(p), stdout, stderr) != 0 {
			return false
		}
		reported = true
	}
	for _, c := range next.Commands {
		status, output := runCommand(cl, p, c, &reported)
		fmt.Fprintf(stdout, "Command %d (%s): %s\n", c.ID, c.Type, status)
		if err := cl.CommandResult(c.ID, status, output); err != nil {
			fmt.Fprintf(stderr, "Warning: result of command %d not delivered: %v\n", c.ID, err)
		}
	}
	return true
}

// runCommand kennt nur die feste Liste; alles andere wird abgelehnt, egal was der Master schickt.
func runCommand(cl *client.Client, p jobs.Paths, c client.Command, reported *bool) (status, output string) {
	if status, output, ok := platformCommand(cl, c); ok {
		return status, output
	}
	switch c.Type {
	case "report_now":
		if *reported {
			return "done", "Report already sent a moment ago."
		}
		var out bytes.Buffer
		code := deliver(cl, daemonSource(p), &out, &out)
		*reported = code == 0
		if code != 0 {
			return "failed", out.String()
		}
		return "done", out.String()
	case "query":
		name := c.Params["name"]
		if !queries.Names[name] {
			return "rejected", fmt.Sprintf("unknown query %q", name)
		}
		nonce := jobs.NewNonce()
		if err := p.Submit(jobs.Request{Nonce: nonce, Query: name}); err != nil {
			return "failed", err.Error()
		}
		res, err := p.Wait(nonce, waitTimeout, waitInterval)
		if err != nil {
			return "failed", err.Error()
		}
		if res.QueryError != "" {
			return "failed", strings.TrimSpace(res.QueryOutput + "\n" + res.QueryError)
		}
		return "done", res.QueryOutput
	case "reboot", "update_agent", "uninstall":
		return runSigned(cl, c)
	}
	return "rejected", fmt.Sprintf("unknown command type %q", c.Type)
}

// actionPaths ist austauschbar für Tests; lastTrustTry verhindert, dass eine abgelehnte Liste ständig neu läuft.
var actionPaths, lastTrustTry = actions.DefaultPaths(), 0

// syncPasskeys reicht eine neuere Passkey-Liste an root weiter; root übernimmt sie nur signiert
// (oder als allererste Liste).
func syncPasskeys(offer *client.TrustOffer, stdout, stderr io.Writer) {
	if !signedActions || offer == nil || offer.Rev <= actionPaths.TrustRev() || offer.Rev == lastTrustTry {
		return
	}
	lastTrustTry = offer.Rev
	nonce := jobs.NewNonce()
	if err := actionPaths.Submit(actions.Request{Nonce: nonce, Kind: "passkeys", Envelope: offer.Envelope, Assertion: offer.Assertion}); err != nil {
		fmt.Fprintf(stderr, "Warning: passkey list not handed over: %v\n", err)
		return
	}
	res, err := actionPaths.Wait(nonce, time.Minute, waitInterval)
	if err != nil {
		fmt.Fprintf(stderr, "Warning: %v\n", err)
		return
	}
	fmt.Fprintf(stdout, "Passkey list revision %d: %s (%s)\n", offer.Rev, res.Status, res.Output)
}

// runSigned reicht einen passkey-bestätigten Befehl an root weiter; geprüft und ausgeführt wird er dort.
func runSigned(cl *client.Client, c client.Command) (status, output string) {
	timeout := time.Minute
	if c.Type == "update_agent" {
		if err := stageUpdate(cl); err != nil {
			return "failed", err.Error()
		}
		timeout = 15 * time.Minute
	}
	nonce := jobs.NewNonce()
	if err := actionPaths.Submit(actions.Request{Nonce: nonce, Kind: "command", Envelope: c.Params["envelope"],
		Assertion: c.Params["assertion"]}); err != nil {
		return "failed", err.Error()
	}
	res, err := actionPaths.Wait(nonce, timeout, waitInterval)
	if err != nil {
		return "failed", err.Error()
	}
	return res.Status, res.Output
}

// stageUpdate lädt Paket und signiertes Manifest herunter; ob sie echt sind, prüft erst root.
func stageUpdate(cl *client.Client) error {
	if err := os.MkdirAll(actionPaths.StageDir, 0o750); err != nil {
		return err
	}
	pkg := "rpm"
	if _, err := os.Stat("/usr/bin/dpkg"); err == nil {
		pkg = "deb"
	}
	files := [][2]string{
		{"/api/agent/release/manifest.json", "manifest.json"},
		{"/api/agent/release/manifest.json.sig", "manifest.json.sig"},
		{"/api/agent/download/" + runtime.GOARCH + "." + pkg, actions.PackageName(runtime.GOARCH, pkg)},
	}
	for _, f := range files {
		if err := cl.Download(f[0], filepath.Join(actionPaths.StageDir, f[1]), 300<<20); err != nil {
			return err
		}
	}
	return nil
}

// runActionJob läuft als root ohne Netz (lablantern-action.service).
func runActionJob(stderr io.Writer) int {
	cfg, err := config.LoadConfig("/etc/lablantern/agent.json")
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	env := actions.DefaultEnv(cfg.SystemID, AgentVersion)
	env.FirstTrustSHA256 = cfg.PasskeysSHA256
	if err := env.Handle(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// runCollectJob läuft als root ohne Netz (lablantern-collect.service) und arbeitet einen Auftrag ab.
func runCollectJob(stderr io.Writer, env collector.Env, p jobs.Paths) int {
	req, err := p.Take()
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if err := p.Execute(req, func() *collector.HostReport { return collector.Collect(env, AgentVersion) }, imageSBOM); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
