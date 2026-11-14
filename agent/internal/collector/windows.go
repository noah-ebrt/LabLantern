package collector

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Windows-Inventar: bewusst schmal. Gemeldet werden Version und Build, ausstehende Sicherheitsupdates laut
// Windows Update, ob ein Neustart aussteht, ob Virenschutz und Firewall an sind und welche Programme für alle
// Benutzer installiert sind. Für die Programme gibt es keine Schwachstellen-Datenbank: Der Master gleicht die
// bekannten unter ihnen mit der Frühwarnung ab. Programme, die nur ein Benutzer für sich installiert hat, fehlen:
// Ihre Registry ist nur geladen, solange er angemeldet ist, die Liste würde mit jeder Anmeldung wechseln.
//
// Das Skript liest nur (Registry, Suche des Windows-Update-Agenten, Zustand von Defender und Firewall). Die Suche braucht das Konto LocalSystem:
// Einem Dienstkonto ohne Rechte verweigert Windows Update sie (E_ACCESSDENIED). Die Ausgabe ist
// Base64 über UTF-8-JSON, damit die Codepage der Konsole Umlaute in Update-Titeln nicht zerstört.
const windowsScript = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$out = @{ os = @{}; updates = @(); reboot = $false; errors = @{}; av = @(); firewall = @(); software = @() }
try {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $out.os = @{
    product = "$($cv.ProductName)"; display_version = "$($cv.DisplayVersion)"; release_id = "$($cv.ReleaseId)"
    build = "$($cv.CurrentBuildNumber)"; ubr = "$($cv.UBR)"; edition = "$($cv.EditionID)"
    installation_type = "$($cv.InstallationType)"
  }
} catch { $out.errors.os = "$_" }
try {
  $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $list = @()
  foreach ($u in $found.Updates) {
    $list += @{
      title = "$($u.Title)"; severity = "$($u.MsrcSeverity)"
      kb = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
      categories = @($u.Categories | ForEach-Object { "$($_.CategoryID)" })
    }
  }
  $out.updates = $list
} catch { $out.errors.updates = "$_" }
try {
  $out.reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
    (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
} catch { $out.errors.reboot = "$_" }
try {
  $mp = Get-MpComputerStatus
  $out.defender = @{
    realtime = [bool]$mp.RealTimeProtectionEnabled; mode = "$($mp.AMRunningMode)"
    signature_age = [long]$mp.AntivirusSignatureAge
  }
} catch { $out.errors.defender = "$_" }
try {
  $out.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
    @{ name = "$($_.displayName)"; state = [int]$_.productState }
  })
} catch { }
try {
  $out.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    @{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') }
  })
} catch { $out.errors.firewall = "$_" }
try {
  $apps = @{}
  foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall') {
    foreach ($key in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
      try {
        $name = "$($key.GetValue('DisplayName'))".Trim()
        if (-not $name -or $key.GetValue('SystemComponent') -eq 1 -or $key.GetValue('ParentKeyName')) { continue }
        $version = "$($key.GetValue('DisplayVersion'))".Trim()
        $apps["$name|$version"] = @{ name = $name; version = $version; publisher = "$($key.GetValue('Publisher'))".Trim() }
      } catch { }
    }
  }
  $out.software = @($apps.Values)
} catch { $out.errors.software = "$_" }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Depth 6 -Compress)))
`

// encodedWindowsScript ist das Skript für `powershell -EncodedCommand` (Base64 über UTF-16LE): So muss nichts
// für die Kommandozeile maskiert werden.
func encodedWindowsScript() string {
	units := utf16.Encode([]rune(windowsScript))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// Klassifikationen von Windows Update, die als Sicherheitsupdate zählen. Die IDs sind in jeder Sprache gleich,
// die Namen nicht.
var winSecurityCategories = map[string]bool{
	"0fa1201d-4330-4fa8-8ae9-b877473b6441": true, // Security Updates (auch das monatliche kumulative Update)
	"e6cf1350-c01b-414d-a61f-263d14d133b4": true, // Critical Updates
}

// strList nimmt, was ConvertTo-Json aus einer Liste macht: ein Array, einen einzelnen Wert oder null.
type strList []string

func (l *strList) UnmarshalJSON(data []byte) error {
	var many []string
	if json.Unmarshal(data, &many) == nil {
		*l = many
		return nil
	}
	var one string
	if json.Unmarshal(data, &one) == nil && one != "" {
		*l = []string{one}
	}
	return nil
}

type winUpdate struct {
	Title      string  `json:"title"`
	Severity   string  `json:"severity"`
	KB         strList `json:"kb"`
	Categories strList `json:"categories"`
}

// winUpdates: wie strList, für die Liste der Updates (ein einzelnes Update kommt als Objekt).
type winUpdates []winUpdate

func (l *winUpdates) UnmarshalJSON(data []byte) error {
	var many []winUpdate
	if json.Unmarshal(data, &many) == nil {
		*l = many
		return nil
	}
	var one winUpdate
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = []winUpdate{one}
	return nil
}

type winInventory struct {
	OS struct {
		Product          string `json:"product"`
		DisplayVersion   string `json:"display_version"`
		ReleaseID        string `json:"release_id"`
		Build            string `json:"build"`
		UBR              string `json:"ubr"`
		Edition          string `json:"edition"`
		InstallationType string `json:"installation_type"`
	} `json:"os"`
	Updates  winUpdates `json:"updates"`
	Reboot   bool       `json:"reboot"`
	Defender *struct {
		Realtime     bool   `json:"realtime"`
		Mode         string `json:"mode"`
		SignatureAge int64  `json:"signature_age"`
	} `json:"defender"`
	AV       winList[winAV]        `json:"av"`
	Firewall winList[winProfile]   `json:"firewall"`
	Software winList[SoftwareInfo] `json:"software"`
	Errors   map[string]string     `json:"errors"`
}

// Eintrag des Windows-Sicherheitscenters (nur auf Clients): productState ist ein Bitfeld, 0x1000 heißt
// eingeschaltet, 0x10 Signaturen veraltet.
type winAV struct {
	Name  string `json:"name"`
	State int    `json:"state"`
}

type winProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// winList: wie winUpdates für beliebige Einträge; was sich nicht lesen lässt, bleibt leer statt den ganzen
// Report zu kippen.
type winList[T any] []T

func (l *winList[T]) UnmarshalJSON(data []byte) error {
	var many []T
	if json.Unmarshal(data, &many) == nil {
		*l = many
		return nil
	}
	var one T
	if string(data) != "null" && json.Unmarshal(data, &one) == nil {
		*l = []T{one}
	}
	return nil
}

const maxSoftware = 2000

func unreadable(what, msg string) string {
	if msg = strings.TrimSpace(msg); msg == "" {
		return what + " state not readable"
	}
	return clip(what+" state not readable: "+msg, 140)
}

// protection bewertet Virenschutz und Firewall. "unknown" heißt nicht lesbar, nie "an".
func (inv winInventory) protection() *Protection {
	p := &Protection{Antivirus: "unknown", Firewall: "unknown"}
	var others []winAV // Virenschutz anderer Hersteller: Defender läuft dann passiv mit
	for _, a := range inv.AV {
		if a.Name != "" && !strings.Contains(strings.ToLower(a.Name), "defender") {
			others = append(others, a)
		}
	}
	switch {
	case inv.Defender != nil && inv.Defender.Realtime:
		age := int(min(max(inv.Defender.SignatureAge, 0), 9999)) // ohne Signaturen meldet Defender 4294967295
		p.Antivirus, p.AntivirusName, p.SignatureAgeDays = "on", "Microsoft Defender", &age
	case len(others) > 0:
		p.Antivirus, p.AntivirusName = "off", others[0].Name
		for _, a := range others {
			if a.State&0x1000 != 0 {
				p.Antivirus, p.AntivirusName, p.AntivirusOutdated = "on", a.Name, a.State&0x10 != 0
				break
			}
		}
	case inv.Defender != nil:
		p.Antivirus, p.AntivirusName = "off", "Microsoft Defender"
	default:
		p.Detail = unreadable("antivirus", inv.Errors["defender"])
	}
	p.AntivirusName = clip(p.AntivirusName, 100)
	if msg := inv.Errors["firewall"]; msg != "" || len(inv.Firewall) == 0 {
		p.Detail = clip(strings.TrimPrefix(p.Detail+"; "+unreadable("firewall", msg), "; "), 300)
		return p
	}
	p.Firewall = "on"
	for _, f := range inv.Firewall {
		if !f.Enabled {
			p.Firewall = "off"
			p.FirewallOff = append(p.FirewallOff, clip(f.Name, 40))
		}
	}
	return p
}

func (inv winInventory) software() []SoftwareInfo {
	out := make([]SoftwareInfo, 0, len(inv.Software))
	for _, a := range inv.Software {
		if a.Name == "" {
			continue
		}
		out = append(out, SoftwareInfo{Name: clip(a.Name, 200), Version: clip(a.Version, 60), Publisher: clip(a.Publisher, 100)})
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].Version < out[j].Version
	})
	if len(out) > maxSoftware {
		out = out[:maxSoftware]
	}
	return out
}

func (u winUpdate) security() bool {
	if u.Severity != "" {
		return true
	}
	for _, c := range u.Categories {
		if winSecurityCategories[strings.ToLower(c)] {
			return true
		}
	}
	return false
}

var winServerYear = regexp.MustCompile(`Server (\d{4})( R2)?`)

// windowsRelease liefert os_id, os_version_id und den Anzeigenamen. os_version_id folgt den Namen von
// endoflife.date (windows: "11-24h2-w", "10-22h2"; windows-server: "2022"), damit der Master das Supportende
// findet; "" heißt: Linie nicht erkannt, dann gibt es keine EOL-Aussage.
func windowsRelease(product, displayVersion, releaseID, build, edition, installationType string) (id, versionID, name string) {
	version := displayVersion
	if version == "" {
		version = releaseID // bis Windows 10 20H1 steht die Version nur hier
	}
	name = strings.TrimSpace(product + " " + version)
	if strings.HasPrefix(installationType, "Server") || strings.Contains(product, "Server") {
		if m := winServerYear.FindStringSubmatch(product); m != nil {
			versionID = m[1]
			if m[2] != "" {
				versionID += "-r2"
			}
		}
		return "windows-server", versionID, strings.TrimSpace(product)
	}
	n, _ := strconv.Atoi(build)
	major := "10"
	if n >= 22000 {
		major = "11"
		// Die Registry nennt auch Windows 11 noch "Windows 10 …"
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if n < 10240 || version == "" {
		return "windows", "", name
	}
	versionID = major + "-" + strings.ToLower(version)
	switch {
	case strings.HasPrefix(edition, "IoTEnterpriseS"):
		versionID += "-iot-lts"
	case strings.HasPrefix(edition, "EnterpriseS"):
		versionID += "-e-lts"
	case major == "10" && strings.EqualFold(version, "22H2"):
		// letzte Windows-10-Version: eine Linie für alle Editionen
	case strings.HasPrefix(edition, "Enterprise"), strings.HasPrefix(edition, "Education"),
		strings.HasPrefix(edition, "IoTEnterprise"):
		versionID += "-e"
	default:
		versionID += "-w"
	}
	return "windows", versionID, name
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// parseWindows trägt die Ausgabe des Skripts in den Report ein. Was nicht ermittelt werden konnte, steht als
// Fehler im Report, nie als "0 Updates".
func parseWindows(out []byte, r *HostReport) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	var inv winInventory
	if err == nil {
		err = json.Unmarshal(raw, &inv)
	}
	if err != nil {
		r.CollectionErrors["packages"] = "Windows inventory unreadable: " + err.Error()
		r.CollectionErrors["security_updates"] = r.CollectionErrors["packages"]
		r.SecurityUpdatesKnown = false
		return
	}
	if msg := inv.Errors["os"]; msg != "" || inv.OS.Build == "" {
		r.CollectionErrors["packages"] = clip("Windows version not detectable: "+msg, 300)
	} else {
		r.OSID, r.OSVersionID, r.OSName = windowsRelease(inv.OS.Product, inv.OS.DisplayVersion, inv.OS.ReleaseID,
			inv.OS.Build, inv.OS.Edition, inv.OS.InstallationType)
		r.Kernel = "10.0." + inv.OS.Build
		if inv.OS.UBR != "" {
			r.Kernel += "." + inv.OS.UBR
		}
	}
	if msg := inv.Errors["updates"]; msg != "" {
		if strings.Contains(strings.ToLower(msg), "80070005") {
			// Dienst noch unter LocalService (angelegt von 0.20.0): Das behebt nur ein Lauf als Administrator
			msg = "access denied. The agent service must run as LocalSystem: on the host, run the update command " +
				"from LabLantern → Add host → Windows once in an administrator PowerShell"
		}
		r.CollectionErrors["security_updates"] = clip("Windows Update could not be queried: "+msg, 300)
		r.SecurityUpdatesKnown = false
	} else {
		for _, u := range inv.Updates {
			if !u.security() {
				continue // Treiber, Vorschau- und Funktionsupdates zählen nicht als Sicherheitsupdate
			}
			title := u.Title
			if title == "" {
				title = strings.Join(u.KB, " ")
			}
			if title == "" {
				title = "unnamed update"
			}
			r.SecurityUpdates = append(r.SecurityUpdates, UpdateInfo{Name: clip(title, 200)})
		}
		r.SecurityUpdatesCount = len(r.SecurityUpdates)
	}
	// Schlägt nur die Abfrage des Neustarts fehl, bleibt er "nein": dafür gibt es keinen eigenen Fehlerkanal.
	r.RebootRequired = inv.Reboot
	r.Protection = inv.protection()
	r.Software = inv.software()
}

func collectWindows(env Env, r *HostReport) {
	out, err := env.WindowsInventory()
	if err != nil {
		msg := clip(fmt.Sprintf("Windows inventory failed: %v", err), 300)
		r.CollectionErrors["packages"], r.CollectionErrors["security_updates"] = msg, msg
		r.SecurityUpdatesKnown = false
		return
	}
	parseWindows(out, r)
}
