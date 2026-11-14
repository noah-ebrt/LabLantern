package collector

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func winEnv(json string) Env {
	return Env{WindowsInventory: func() ([]byte, error) {
		return []byte(base64.StdEncoding.EncodeToString([]byte(json)) + "\r\n"), nil
	}}
}

const winOS = `"os":{"product":"Windows 10 Pro","display_version":"24H2","release_id":"2009","build":"26100","ubr":"2314","edition":"Professional","installation_type":"Client"}`

func TestWindowsReportCountsOnlySecurityUpdates(t *testing.T) {
	r := Collect(winEnv(`{`+winOS+`,"reboot":true,"errors":{},"updates":[
		{"title":"2026-11 Cumulative Update for Windows 11 (KB5000001)","severity":"Critical","kb":["KB5000001"],"categories":["0FA1201D-4330-4FA8-8AE9-B877473B6441"]},
		{"title":"Update für Gerät","severity":"","kb":[],"categories":["ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0"]},
		{"title":"Critical fix (KB5000002)","severity":"","kb":"KB5000002","categories":"e6cf1350-c01b-414d-a61f-263d14d133b4"}]}`), "1.2.3")
	if len(r.CollectionErrors) != 0 || !r.SecurityUpdatesKnown {
		t.Fatalf("unexpected errors: %v", r.CollectionErrors)
	}
	if r.SecurityUpdatesCount != 2 || len(r.SecurityUpdates) != 2 ||
		r.SecurityUpdates[0].Name != "2026-11 Cumulative Update for Windows 11 (KB5000001)" {
		t.Fatalf("security updates = %+v", r.SecurityUpdates)
	}
	if !r.RebootRequired || r.AgentVersion != "1.2.3" || len(r.Packages) != 0 || len(r.Containers) != 0 {
		t.Fatalf("report = %+v", r)
	}
	// Windows 11 heißt in der Registry noch "Windows 10"
	if r.OSID != "windows" || r.OSVersionID != "11-24h2-w" || r.OSName != "Windows 11 Pro 24H2" || r.Kernel != "10.0.26100.2314" {
		t.Fatalf("os = %q %q %q %q", r.OSID, r.OSVersionID, r.OSName, r.Kernel)
	}
}

func TestWindowsSingleUpdateArrivesAsObject(t *testing.T) {
	r := Collect(winEnv(`{`+winOS+`,"reboot":false,"errors":{},"updates":{"title":"Fix","severity":"Important","kb":null,"categories":null}}`), "x")
	if r.SecurityUpdatesCount != 1 || len(r.CollectionErrors) != 0 {
		t.Fatalf("count = %d, errors = %v", r.SecurityUpdatesCount, r.CollectionErrors)
	}
}

func TestWindowsUpdateErrorIsNotZeroUpdates(t *testing.T) {
	r := Collect(winEnv(`{`+winOS+`,"reboot":false,"updates":[],"errors":{"updates":"Access is denied."}}`), "x")
	if r.SecurityUpdatesKnown || !strings.Contains(r.CollectionErrors["security_updates"], "Access is denied") {
		t.Fatalf("known = %v, errors = %v", r.SecurityUpdatesKnown, r.CollectionErrors)
	}
	if r.CollectionErrors["packages"] != "" || r.OSID != "windows" {
		t.Fatalf("the OS part must stay usable: %v", r.CollectionErrors)
	}
}

func TestWindowsAccessDeniedNamesTheFix(t *testing.T) {
	// so meldete es ein deutsches Windows, als der Dienst noch unter LocalService lief
	r := Collect(winEnv(`{`+winOS+`,"reboot":false,"updates":[],"errors":{"updates":"Zugriff verweigert (Ausnahme von HRESULT: 0x80070005 (E_ACCESSDENIED))"}}`), "x")
	msg := r.CollectionErrors["security_updates"]
	if r.SecurityUpdatesKnown || !strings.Contains(msg, "LocalSystem") || !strings.Contains(msg, "administrator PowerShell") {
		t.Fatalf("known = %v, message = %q", r.SecurityUpdatesKnown, msg)
	}
}

func TestWindowsInventoryFailureAndGarbageAreErrors(t *testing.T) {
	failed := Collect(Env{WindowsInventory: func() ([]byte, error) { return nil, errors.New("powershell missing") }}, "x")
	garbage := Collect(Env{WindowsInventory: func() ([]byte, error) { return []byte("not base64 !"), nil }}, "x")
	for _, r := range []*HostReport{failed, garbage} {
		if r.SecurityUpdatesKnown || r.CollectionErrors["packages"] == "" || r.CollectionErrors["security_updates"] == "" {
			t.Fatalf("known = %v, errors = %v", r.SecurityUpdatesKnown, r.CollectionErrors)
		}
	}
}

func TestWindowsReleaseNamesFollowEndoflifeDate(t *testing.T) {
	cases := []struct{ product, display, releaseID, build, edition, kind, id, version, name string }{
		{"Windows 10 Home", "25H2", "2009", "26200", "Core", "Client", "windows", "11-25h2-w", "Windows 11 Home 25H2"},
		{"Windows 10 Enterprise", "24H2", "2009", "26100", "Enterprise", "Client", "windows", "11-24h2-e", "Windows 11 Enterprise 24H2"},
		{"Windows 10 Enterprise LTSC 2024", "24H2", "2009", "26100", "EnterpriseS", "Client", "windows", "11-24h2-e-lts", "Windows 11 Enterprise LTSC 2024 24H2"},
		{"Windows 10 Pro", "22H2", "2009", "19045", "Professional", "Client", "windows", "10-22h2", "Windows 10 Pro 22H2"},
		{"Windows 10 Education", "", "1909", "18363", "Education", "Client", "windows", "10-1909-e", "Windows 10 Education 1909"},
		{"Windows Server 2022 Standard", "21H2", "2009", "20348", "ServerStandard", "Server", "windows-server", "2022", "Windows Server 2022 Standard"},
		{"Windows Server 2012 R2 Datacenter", "", "", "9600", "ServerDatacenter", "Server Core", "windows-server", "2012-r2", "Windows Server 2012 R2 Datacenter"},
		{"Windows 8.1 Pro", "", "", "9600", "Professional", "Client", "windows", "", "Windows 8.1 Pro"},
	}
	for _, c := range cases {
		id, version, name := windowsRelease(c.product, c.display, c.releaseID, c.build, c.edition, c.kind)
		if id != c.id || version != c.version || name != c.name {
			t.Errorf("%s (%s): got %q %q %q, want %q %q %q", c.product, c.build, id, version, name, c.id, c.version, c.name)
		}
	}
}

func TestEncodedWindowsScriptIsUTF16LEBase64(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(encodedWindowsScript())
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("not base64 over UTF-16: %v", err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if got := string(utf16.Decode(units)); got != windowsScript {
		t.Fatal("decoded script differs from the source")
	}
	// Das Skript liest nur: nichts, was Updates lädt oder installiert, nichts aus dem Netz nachlädt
	for _, bad := range []string{"UpdateInstaller", "UpdateDownloader", "Invoke-", "Start-Process", "Set-Item", "New-Item", "Remove-"} {
		if strings.Contains(windowsScript, bad) {
			t.Errorf("script contains %q", bad)
		}
	}
}

const winOK = `{` + winOS + `,"reboot":false,"updates":[],"errors":{}`

func TestWindowsProtectionFromDefenderAndFirewall(t *testing.T) {
	r := Collect(winEnv(winOK+`,"defender":{"realtime":true,"mode":"Normal","signature_age":1},
		"av":{"name":"Windows Defender","state":397568},
		"firewall":[{"name":"Domain","enabled":true},{"name":"Private","enabled":true},{"name":"Public","enabled":false}]}`), "x")
	p := r.Protection
	if p == nil || p.Antivirus != "on" || p.AntivirusName != "Microsoft Defender" || p.SignatureAgeDays == nil || *p.SignatureAgeDays != 1 {
		t.Fatalf("antivirus = %+v", p)
	}
	if p.Firewall != "off" || len(p.FirewallOff) != 1 || p.FirewallOff[0] != "Public" || p.Detail != "" {
		t.Fatalf("firewall = %+v", p)
	}
	if len(r.CollectionErrors) != 0 {
		t.Fatalf("errors = %v", r.CollectionErrors)
	}
}

func TestWindowsProtectionWithAnotherAntivirus(t *testing.T) {
	fw := `"firewall":[{"name":"Public","enabled":true}]`
	// Defender passiv, das andere Produkt an (0x1000) mit veralteten Signaturen (0x10)
	r := Collect(winEnv(winOK+`,"defender":{"realtime":false,"mode":"Passive Mode","signature_age":3},
		"av":[{"name":"Windows Defender","state":393472},{"name":"Other AV","state":266256}],`+fw+`}`), "x")
	if p := r.Protection; p.Antivirus != "on" || p.AntivirusName != "Other AV" || !p.AntivirusOutdated || p.SignatureAgeDays != nil || p.Firewall != "on" {
		t.Fatalf("third party on = %+v", p)
	}
	r = Collect(winEnv(winOK+`,"defender":{"realtime":false,"mode":"Passive Mode","signature_age":3},
		"av":[{"name":"Other AV","state":262144}],`+fw+`}`), "x")
	if p := r.Protection; p.Antivirus != "off" || p.AntivirusName != "Other AV" {
		t.Fatalf("third party off = %+v", p)
	}
	r = Collect(winEnv(winOK+`,"defender":{"realtime":false,"mode":"Normal","signature_age":4294967295},"av":[],`+fw+`}`), "x")
	if p := r.Protection; p.Antivirus != "off" || p.AntivirusName != "Microsoft Defender" {
		t.Fatalf("defender off = %+v", p)
	}
}

// Nicht lesbar ist nie "an": weder ohne Defender-Modul (Server) noch bei einem Fehler der Firewall-Abfrage
func TestWindowsProtectionUnreadableIsUnknown(t *testing.T) {
	r := Collect(winEnv(`{`+winOS+`,"reboot":false,"updates":[],"av":[],"firewall":[],
		"errors":{"defender":"The term 'Get-MpComputerStatus' is not recognized","firewall":"Access denied"}}`), "x")
	p := r.Protection
	if p.Antivirus != "unknown" || p.Firewall != "unknown" || !strings.Contains(p.Detail, "Get-MpComputerStatus") ||
		!strings.Contains(p.Detail, "firewall state not readable: Access denied") {
		t.Fatalf("protection = %+v", p)
	}
	// ein Report eines alten Skripts ohne die Felder: ebenfalls unbekannt
	if p := Collect(winEnv(winOK+`}`), "x").Protection; p.Antivirus != "unknown" || p.Firewall != "unknown" {
		t.Fatalf("old script = %+v", p)
	}
}

func TestWindowsSoftwareIsSortedAndClipped(t *testing.T) {
	long := strings.Repeat("x", 300)
	r := Collect(winEnv(winOK+`,"software":[{"name":"Zeta Tool","version":"2.0","publisher":"Example"},
		{"name":"alpha app","version":"1.2.3","publisher":""},{"name":"","version":"9"},
		{"name":"`+long+`","version":"`+long+`","publisher":"`+long+`"}]}`), "x")
	if len(r.Software) != 3 || r.Software[0].Name != "alpha app" || r.Software[0].Version != "1.2.3" || r.Software[2].Name != "Zeta Tool" {
		t.Fatalf("software = %+v", r.Software)
	}
	if s := r.Software[1]; len(s.Name) != 200 || len(s.Version) != 60 || len(s.Publisher) != 100 {
		t.Fatalf("not clipped: %d %d %d", len(s.Name), len(s.Version), len(s.Publisher))
	}
	// ein einzelnes Programm kommt als Objekt
	if r := Collect(winEnv(winOK+`,"software":{"name":"Only One","version":"1"}}`), "x"); len(r.Software) != 1 {
		t.Fatalf("single = %+v", r.Software)
	}
}
