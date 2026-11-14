//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"lablantern/agent/internal/client"
	"lablantern/agent/internal/collector"
	"lablantern/agent/internal/config"
	"lablantern/agent/internal/jobs"
	"lablantern/agent/internal/release"
)

// Der Windows-Agent ist bewusst schmal: ein einziger Dienst, der nur liest und meldet. Er läuft als LocalSystem,
// weil Windows Update die Suche nach ausstehenden Updates einem Dienstkonto ohne Rechte verweigert (gemessen mit
// LocalService in 0.20.0: E_ACCESSDENIED). Anders als unter Linux sind Netz und Rechte hier also nicht getrennt.
// Dafür nimmt er vom Master nur zwei Befehle an: jetzt melden und sich aktualisieren, Letzteres nur auf ein
// Release, das mit dem Schlüssel dieser Installation signiert und neuer ist. Neustart, Abfragen und Entfernen
// lehnt er ab, weil er Passkeys nicht prüft.

const serviceName = "LabLanternAgent"

const usage = `lablantern-agent %s – push agent for Windows: version, pending security updates, reboot state

Usage (in a PowerShell opened with "Run as administrator"):
  lablantern-agent setup [--master <URL> [--ca-fingerprint <FP>]]
                                   (pair with a code, then install and start the service)
  lablantern-agent enroll --server <URL> --token <TOKEN> --ca-fingerprint <FP>
                                   (one-time token instead of a code, then install and start the service)
  lablantern-agent install         (copy this file into place and restart the service; keeps the configuration)
  lablantern-agent uninstall       (remove the service, the program and the configuration)
  lablantern-agent scan            (collect and report now)
  lablantern-agent version

The LabLantern web UI shows the complete setup command under Systems → Add host → Windows.
`

// signedActions: Unter Windows gibt es keinen Teil, der passkey-bestätigte Befehle ausführen dürfte.
const signedActions = false

var imageSBOM = func(string) ([]byte, error) {
	return nil, errors.New("image SBOMs are not supported on Windows")
}

// daemonSource: Der Dienst sammelt selbst, es gibt keinen getrennten Sammler.
func daemonSource(jobs.Paths) source { return inProcess(collector.DefaultEnv()) }

func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "LabLantern")
}

func installedExe() string { return filepath.Join(installDir(), "lablantern-agent.exe") }
func dataDir() string      { return filepath.Dir(config.SystemConfigPath()) }

func requireAdmin() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return errors.New(`administrator rights needed: open PowerShell with "Run as administrator" and run the command again`)
}

// startDaemon richtet nach setup/enroll den Dienst ein und startet ihn.
var startDaemon = func() (string, error) {
	if err := install(); err != nil {
		return "", fmt.Errorf("configuration saved, but the service could not be installed: %w", err)
	}
	return "Service " + serviceName + " installed and started", nil
}

// alreadySetUp: Wer den Einrichtungsbefehl auf einem gepaarten Host noch einmal ausführt, will meist die neue
// Version. Statt abzulehnen, wird deshalb Programm und Dienst erneuert; das Pairing bleibt.
func alreadySetUp(configPath string, stdout, stderr io.Writer) (int, bool) {
	if !strings.EqualFold(filepath.Clean(configPath), config.SystemConfigPath()) {
		return 0, false
	}
	fmt.Fprintln(stdout, "This host is already paired: updating the program and the service. Add --force to pair it again instead.")
	if err := install(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, true
	}
	fmt.Fprintf(stdout, "✓ Service %s runs version %s; it reports within a few minutes.\n", serviceName, AgentVersion)
	return 0, true
}

func platformCLI(args []string, stdout, stderr io.Writer) (int, bool) {
	var do func() error
	var done string
	switch args[0] {
	case "install":
		do, done = install, "Service "+serviceName+" installed and started."
	case "uninstall":
		do, done = uninstall, "LabLantern agent removed. Delete the host in the LabLantern web UI as well."
	default:
		return 0, false
	}
	err := requireAdmin()
	if err == nil {
		err = do()
	}
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1, true
	}
	fmt.Fprintln(stdout, "✓ "+done)
	if _, err := os.Stat(config.SystemConfigPath()); args[0] == "install" && err != nil {
		fmt.Fprintln(stdout, "This host is not paired yet: run 'lablantern-agent setup' with the options from the web UI.")
	}
	return 0, true
}

// stopService hält den Dienst an und wartet, bis auch sein Prozess beendet ist: Erst dann ist die Programmdatei
// frei. "Gestoppt" meldet der Dienst kurz vor dem Ende des Prozesses; hängt der danach noch, wird er beendet.
func stopService(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("cannot query the service: %w", err)
	}
	pid := st.ProcessId
	if st.State != svc.Stopped {
		if st, err = s.Control(svc.Stop); err != nil {
			return fmt.Errorf("cannot stop the service: %w", err)
		}
		for i := 0; st.State != svc.Stopped && i < 120; i++ {
			time.Sleep(250 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				return fmt.Errorf("cannot query the service: %w", err)
			}
		}
		if st.State != svc.Stopped {
			return fmt.Errorf("the service did not stop within 30 seconds (state %d)", st.State)
		}
	}
	if pid == 0 {
		return nil
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return nil // schon beendet
	}
	defer windows.CloseHandle(h)
	if ev, _ := windows.WaitForSingleObject(h, 10_000); ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(h, 1)
		_, _ = windows.WaitForSingleObject(h, 5_000)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// replaceProgram bringt diese Datei an ihren Platz. Erst wird sie daneben geschrieben (zeigt, ob das Verzeichnis
// überhaupt beschreibbar ist), dann ersetzt sie die alte; ist die noch geladen, wird die alte beiseite geschoben.
// Sperren durch Virenscanner sind meist kurz, deshalb mehrere Versuche. Kein Schritt scheitert stillschweigend.
func replaceProgram(self, target string) error {
	fresh, old := target+".new", target+".old"
	var last error
	for i := 0; i < 20; i++ {
		if i > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		_ = os.Remove(old)
		if err := copyFile(self, fresh); err != nil {
			last = err
			continue
		}
		err := os.Rename(fresh, target)
		if err == nil {
			return nil
		}
		if aside := os.Rename(target, old); aside != nil {
			last = fmt.Errorf("%v; %v", err, aside)
			continue
		}
		if err := os.Rename(fresh, target); err != nil {
			_ = os.Rename(old, target)
			last = err
			continue
		}
		_ = os.Remove(old)
		return nil
	}
	_ = os.Remove(fresh)
	return last
}

// installState beschreibt für eine Fehlermeldung, was im Programmverzeichnis liegt und wer es darf.
func installState() string {
	var b strings.Builder
	icacls := filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe")
	for _, path := range []string{installDir(), installedExe()} {
		out, _ := exec.Command(icacls, path).CombinedOutput()
		b.WriteString(strings.TrimSpace(string(out)) + "\n")
	}
	if entries, err := os.ReadDir(installDir()); err == nil {
		for _, e := range entries {
			b.WriteString("  file: " + e.Name() + "\n")
		}
	}
	return b.String()
}

func sameFile(a, b string) bool {
	x, err1 := os.Stat(a)
	y, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(x, y)
}

// install kopiert diese Datei nach %ProgramFiles%\LabLantern, legt den Dienst an (oder lässt den vorhandenen
// stehen) und startet ihn. Wiederholbar: So wird auch von Hand aktualisiert.
func install() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		err = stopService(s) // gibt die Programmdatei frei
		s.Close()
		if err != nil {
			return err
		}
	}
	// Das Programmverzeichnis bekommt die Rechte, die %ProgramFiles% vererbt (schreiben: nur Administratoren und
	// SYSTEM). Ein neues Verzeichnis hat sie von selbst; ein vorhandenes wird darauf zurückgesetzt, das räumt auch
	// weg, was 0.20.0 dem Konto LocalService gegeben hat, und repariert Dateien, die 0.20.1 unzugänglich machte.
	_, statErr := os.Stat(installDir())
	if err := os.MkdirAll(installDir(), 0o755); err != nil {
		return err
	}
	if statErr == nil {
		if err := config.Inherit(installDir()); err != nil {
			return err
		}
	}
	if _, err := os.Stat(dataDir()); err == nil {
		if err := config.Restrict(dataDir()); err != nil {
			return err
		}
	}
	target := installedExe()
	if !sameFile(self, target) {
		if err := replaceProgram(self, target); err != nil {
			return fmt.Errorf("cannot copy the program to %s: %w\nState of the program directory, for diagnosis:\n%s",
				target, err, installState())
		}
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, target, mgr.Config{
			DisplayName: "LabLantern Agent",
			Description: "Reports the Windows version, pending security updates and the reboot state to the LabLantern master.",
			StartType:   mgr.StartAutomatic, // ohne Kontoangabe: LocalSystem
		}, "daemon")
		if err != nil {
			return fmt.Errorf("cannot create the service: %w", err)
		}
	} else if c, err := s.Config(); err == nil && !strings.EqualFold(c.ServiceStartName, "LocalSystem") {
		// von 0.20.0 angelegt: lief unter LocalService und bekam von Windows Update keine Auskunft
		c.ServiceStartName = "LocalSystem"
		if err := s.UpdateConfig(c); err != nil {
			s.Close()
			return fmt.Errorf("cannot switch the service to the LocalSystem account: %w", err)
		}
	}
	defer s.Close()
	// Endet der Prozess, ohne "gestoppt" zu melden (Fehler oder Selbst-Update), startet Windows ihn neu
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 3600); err != nil {
		return fmt.Errorf("cannot set the restart rule of the service: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("cannot start the service: %w", err)
	}
	return nil
}

// uninstall entfernt Dienst, Konfiguration (Token, CA) und Programm samt Protokoll.
func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager: %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		err = stopService(s)
		if err == nil {
			err = s.Delete()
		}
		s.Close()
		if err != nil {
			return fmt.Errorf("cannot remove the service: %w", err)
		}
	}
	if err := os.RemoveAll(dataDir()); err != nil {
		return err
	}
	dir := installDir()
	if os.RemoveAll(dir) == nil {
		return nil
	}
	// Läuft gerade die installierte Datei selbst, kann sie sich nicht löschen: ein kurzer Nachläufer räumt auf.
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CmdLine: `cmd.exe /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "` + dir + `"`}
	return cmd.Start()
}

// platformCommand: Befehle des Masters. report_now läuft wie überall; ein Update prüft der Agent selbst gegen
// den Release-Schlüssel; alles, was Rechte bräuchte, lehnt er ab.
func platformCommand(cl *client.Client, c client.Command) (string, string, bool) {
	switch c.Type {
	case "update_agent":
		status, output := selfUpdate(cl)
		return status, output, true
	case "query", "reboot", "uninstall":
		return "rejected", "not supported by the Windows agent (it only reports and updates itself)", true
	}
	return "", "", false
}

// selfUpdate lädt Manifest, Signatur und Programm, prüft sie wie der root-Teil unter Linux (Signatur mit dem
// Schlüssel dieser Installation, neuer als die laufende Version, Prüfsumme) und tauscht dann die eigene Datei.
// Der Passkey des Admins wird hier nicht geprüft: Mehr als ein echtes, neueres Release kann der Befehl nicht
// bewirken, auch wenn ihn ein übernommener Master schickt.
func selfUpdate(cl *client.Client) (string, string) {
	pub := release.PublicKey()
	if pub == nil {
		return "rejected", "this build carries no release key and accepts no updates"
	}
	self, err := os.Executable()
	if err != nil {
		return "failed", err.Error()
	}
	work, err := os.MkdirTemp(filepath.Dir(self), "update-")
	if err != nil {
		return "failed", err.Error()
	}
	defer os.RemoveAll(work)
	name := fmt.Sprintf("lablantern-agent-windows-%s.exe", runtime.GOARCH)
	for _, f := range [][2]string{
		{"/api/agent/release/manifest.json", "manifest.json"},
		{"/api/agent/release/manifest.json.sig", "manifest.json.sig"},
		{"/api/agent/download/windows-" + runtime.GOARCH + ".exe", name},
	} {
		if err := cl.Download(f[0], filepath.Join(work, f[1]), 300<<20); err != nil {
			return "failed", err.Error()
		}
	}
	manifest, _ := os.ReadFile(filepath.Join(work, "manifest.json"))
	sig, _ := os.ReadFile(filepath.Join(work, "manifest.json.sig"))
	m, err := release.Verify(manifest, sig, pub)
	switch {
	case err != nil:
		return "rejected", err.Error()
	case !release.Newer(m.Version, AgentVersion):
		return "rejected", fmt.Sprintf("release %s is not newer than the running %s", m.Version, AgentVersion)
	}
	fresh := filepath.Join(work, name)
	if err := m.CheckFile(name, fresh); err != nil {
		return "rejected", err.Error()
	}
	old := self + ".old"
	_ = os.Remove(old)
	if err := os.Rename(self, old); err != nil {
		return "failed", err.Error()
	}
	if err := os.Rename(fresh, self); err != nil {
		_ = os.Rename(old, self)
		return "failed", err.Error()
	}
	restartRequested = true
	return "done", "Installed version " + m.Version
}

// logWriter schreibt das Protokoll des Dienstes (agent.log neben dem Programm) mit Zeitstempel und
// beginnt bei 1 MB von vorn.
type logWriter struct {
	mu sync.Mutex
	f  *os.File
}

func (l *logWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return len(p), nil
	}
	if st, err := l.f.Stat(); err == nil && st.Size() > 1<<20 {
		_ = l.f.Truncate(0)
	}
	line := time.Now().Format("2006-01-02 15:04:05 ") + strings.TrimRight(string(p), "\r\n") + "\r\n"
	_, _ = l.f.WriteString(line)
	return len(p), nil
}

type service struct{ log io.Writer }

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	go func() {
		code := run(os.Args[1:], s.log, s.log, collector.DefaultEnv())
		// Der Daemon endet von selbst nur nach einem Update oder einem Fehler. Ohne "gestoppt" zu melden beenden:
		// Dann greift die Neustart-Regel des Dienstes.
		if code == 0 {
			code = 1
		}
		os.Exit(code)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range requests {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// serviceMain übernimmt, wenn der Dienstmanager den Prozess gestartet hat.
func serviceMain() (int, bool) {
	if is, err := svc.IsWindowsService(); err != nil || !is {
		return 0, false
	}
	if self, err := os.Executable(); err == nil {
		_ = os.Remove(self + ".old") // Rest des letzten Updates
	}
	f, _ := os.OpenFile(filepath.Join(installDir(), "agent.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	log := &logWriter{f: f}
	fmt.Fprintf(log, "lablantern-agent %s started", AgentVersion)
	if err := svc.Run(serviceName, &service{log: log}); err != nil {
		fmt.Fprintf(log, "service failed: %v", err)
		return 1, true
	}
	return 0, true
}
