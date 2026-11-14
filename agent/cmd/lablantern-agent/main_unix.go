//go:build !windows

package main

import (
	"io"
	"os"
	"os/exec"

	"lablantern/agent/internal/client"
	"lablantern/agent/internal/images"
)

const usage = `lablantern-agent %s – push agent for vulnerabilities and inventory

Usage:
  sudo lablantern-agent setup [--master <URL> [--ca-fingerprint <FP>]] [--passkeys-sha256 <HASH>]
                                   (find the master on the LAN and pair with a code)
  lablantern-agent enroll --server <URL> --token <TOKEN> --ca-fingerprint <FP> [--passkeys-sha256 <HASH>] [--config <PATH>]
  lablantern-agent scan [--config <PATH>]      (as root: collect and report now)
  lablantern-agent daemon           (run by lablantern-agentd.service as user lablantern)
  lablantern-agent collect-job      (run by lablantern-collect.service as root without network)
  lablantern-agent action-job       (run by lablantern-action.service: passkey-confirmed reboot/update)
  lablantern-agent version

The LabLantern web UI shows the complete enroll command including the fingerprint under Systems.
`

// signedActions: Passkey-bestätigte Befehle prüft und führt der root-Teil aus (lablantern-action.service).
const signedActions = true

// imageSBOM ist austauschbar, damit Tests ohne Docker auskommen.
var imageSBOM = images.SyftSBOM

// daemonSource: Der Daemon hat keine Rechte und lässt den Sammler (root, ohne Netz) erheben.
var daemonSource = viaCollector

// serviceMain: Unter Unix startet systemd den Daemon als gewöhnlichen Prozess.
func serviceMain() (int, bool) { return 0, false }

// platformCLI und platformCommand: nur Windows kennt eigene Kommandos und eine eigene Befehlsbehandlung.
func platformCLI([]string, io.Writer, io.Writer) (int, bool) { return 0, false }

func platformCommand(*client.Client, client.Command) (string, string, bool) { return "", "", false }

// alreadySetUp: Unter Unix aktualisiert das Paket den Agenten; setup lehnt einen zweiten Lauf ohne --force ab.
func alreadySetUp(string, io.Writer, io.Writer) (int, bool) { return 0, false }

// requireAdmin: Unter Unix scheitert ohne root erst das Schreiben der Konfiguration, mit klarer Meldung.
func requireAdmin() error { return nil }

// startDaemon startet den Daemon nach setup/enroll neu, wenn das Paket installiert ist (nur als root).
var startDaemon = func() (string, error) {
	if os.Geteuid() != 0 {
		return "", nil
	}
	if _, err := os.Stat("/usr/lib/systemd/system/lablantern-agentd.service"); err != nil {
		return "", nil
	}
	if exec.Command("systemctl", "restart", "lablantern-agentd.service").Run() != nil {
		return "", nil
	}
	return "lablantern-agentd restarted", nil
}
