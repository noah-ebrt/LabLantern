package collector

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
)

// Laufwerke und Pools eines Hosts (ab 0.18), nur auf echter Hardware: In VMs und Containern sind die Laufwerke
// virtuell oder gehören dem Wirt. Gesundheit und Temperatur kommen nur von smartctl, falls installiert; ohne bleibt
// der Zustand leer, und der Master zeigt "unbekannt", nie "gesund". Schlafende Platten weckt der Agent nicht.

type StoragePool struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`             // ZFS pool | RAID
	Vdevs  []string `json:"vdevs"`            // Aufbau der Datenvdevs: RAIDZ1, MIRROR, STRIPE, RAID1 …
	Status string   `json:"status,omitempty"` // ONLINE, DEGRADED … wie vom System gemeldet
	Size   int64    `json:"size,omitempty"`
	Alloc  int64    `json:"alloc,omitempty"`
	Disks  []string `json:"disks"`
}

type StorageDisk struct {
	Name   string `json:"name"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Type   string `json:"type,omitempty"`   // hdd | ssd | nvme
	Status string `json:"status,omitempty"` // Zustand als Mitglied eines Pools
	Smart  string `json:"smart,omitempty"`  // PASSED | FAILED (smartctl)
	Temp   *int   `json:"temp,omitempty"`
	Pool   string `json:"pool,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Storage struct {
	Pools []StoragePool `json:"pools"`
	Disks []StorageDisk `json:"disks"`
	Error string        `json:"error,omitempty"`
}

var groupVdevs = []string{"mirror", "raidz1", "raidz2", "raidz3", "raidz", "draid"}
var zfsRoles = map[string]bool{"logs": true, "cache": true, "spares": true, "special": true, "dedup": true}

func virtualized(env Env) bool {
	if env.Exists("/run/systemd/container") || env.Exists("/.dockerenv") {
		return true
	}
	out, _ := env.Run("systemd-detect-virt") // "none" mit Exit 1 auf echter Hardware
	v := strings.TrimSpace(string(out))
	return v != "" && v != "none"
}

func collectStorage(env Env, r *HostReport) {
	if !lookPath(env, "lsblk") || virtualized(env) {
		return
	}
	st := &Storage{Pools: []StoragePool{}, Disks: []StorageDisk{}}
	r.Storage = st
	out, err := env.Run("lsblk", "-J", "-b", "-d", "-o", "NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,TYPE")
	if err != nil {
		st.Error = "lsblk failed: " + err.Error()
		return
	}
	st.Disks = parseLsblk(out)
	byName := map[string]*StorageDisk{}
	for i := range st.Disks {
		byName[st.Disks[i].Name] = &st.Disks[i]
	}
	if lookPath(env, "zpool") {
		zfsPools(env, st, byName)
	}
	if b, err := env.ReadFile("/proc/mdstat"); err == nil {
		st.Pools = append(st.Pools, parseMdstat(string(b), byName)...)
	}
	if lookPath(env, "smartctl") {
		for i := range st.Disks {
			smart(env, &st.Disks[i])
		}
	}
}

// lsblk gibt je nach Version Zahlen und Wahrheitswerte als Text oder als JSON-Wert aus
func flexInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

func flexBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "1" || x == "true"
	}
	return false
}

func parseLsblk(out []byte) []StorageDisk {
	var doc struct {
		Blockdevices []map[string]any `json:"blockdevices"`
	}
	disks := []StorageDisk{}
	if json.Unmarshal(out, &doc) != nil {
		return disks
	}
	for _, d := range doc.Blockdevices {
		name, _ := d["name"].(string)
		typ, _ := d["type"].(string)
		if typ != "disk" || name == "" {
			continue
		}
		skip := false
		for _, p := range []string{"zram", "loop", "ram", "fd", "sr", "zd", "rbd", "nbd"} {
			skip = skip || strings.HasPrefix(name, p)
		}
		if skip {
			continue
		}
		model, _ := d["model"].(string)
		serial, _ := d["serial"].(string)
		tran, _ := d["tran"].(string)
		kind := "hdd"
		if tran == "nvme" || strings.HasPrefix(name, "nvme") {
			kind = "nvme"
		} else if !flexBool(d["rota"]) {
			kind = "ssd"
		}
		disks = append(disks, StorageDisk{Name: name, Model: strings.TrimSpace(model), Serial: strings.TrimSpace(serial),
			Size: flexInt(d["size"]), Type: kind})
	}
	return disks
}

// Laufwerk zu einem Gerät oder einer Partition: sda3 -> sda, nvme0n1p2 -> nvme0n1
func owner(dev string, byName map[string]*StorageDisk) *StorageDisk {
	base := filepath.Base(dev)
	if d, ok := byName[base]; ok {
		return d
	}
	for name, d := range byName {
		rest := strings.TrimPrefix(strings.TrimPrefix(base, name), "p")
		if strings.HasPrefix(base, name) && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return d
		}
	}
	return nil
}

func zfsPools(env Env, st *Storage, byName map[string]*StorageDisk) {
	out, err := env.Run("zpool", "list", "-H", "-p", "-o", "name,size,alloc,health")
	if err != nil {
		st.Error = "zpool list failed: " + err.Error()
		return
	}
	pools := map[string]*StoragePool{}
	var order []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		size, _ := strconv.ParseInt(f[1], 10, 64)
		alloc, _ := strconv.ParseInt(f[2], 10, 64)
		pools[f[0]] = &StoragePool{Name: f[0], Kind: "ZFS pool", Status: f[3], Size: size, Alloc: alloc, Vdevs: []string{}, Disks: []string{}}
		order = append(order, f[0])
	}
	if status, err := env.Run("zpool", "status", "-P", "-L"); err == nil {
		parseZpoolStatus(string(status), pools, byName)
	}
	for _, name := range order {
		st.Pools = append(st.Pools, *pools[name])
	}
}

// parseZpoolStatus liest den Aufbau aus "zpool status -P -L": Ebene 0 ist der Pool oder eine Rolle (cache, logs …),
// Ebene 1 eine Vdev-Gruppe (mirror-0, raidz1-0) oder ein einzelnes Gerät (Stripe), darunter die Geräte.
func parseZpoolStatus(text string, pools map[string]*StoragePool, byName map[string]*StorageDisk) {
	var pool *StoragePool
	role, inConfig := "", false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "pool:"):
			pool, inConfig = pools[strings.TrimSpace(strings.TrimPrefix(trimmed, "pool:"))], false
			continue
		case strings.HasPrefix(trimmed, "config:"):
			inConfig = true
			continue
		case strings.HasPrefix(trimmed, "errors:"):
			inConfig = false
			continue
		}
		f := strings.Fields(trimmed)
		if pool == nil || !inConfig || len(f) == 0 || f[0] == "NAME" {
			continue
		}
		level := (len(strings.TrimLeft(line, "\t")) - len(strings.TrimLeft(line, " \t"))) / 2
		name := f[0]
		if level == 0 {
			role = "data"
			if name != pool.Name && zfsRoles[name] {
				role = name
			}
			continue
		}
		group := ""
		for _, g := range groupVdevs {
			if strings.HasPrefix(name, g+"-") || strings.HasPrefix(name, g+":") {
				group = strings.ToUpper(g)
			}
		}
		if level == 1 && role == "data" {
			if group != "" {
				pool.Vdevs = append(pool.Vdevs, group)
			} else {
				pool.Vdevs = append(pool.Vdevs, "STRIPE")
			}
		}
		if group != "" {
			continue
		}
		d := owner(name, byName)
		if d == nil {
			continue
		}
		d.Pool = pool.Name
		if len(f) > 1 {
			d.Status = f[1]
		}
		var details []string
		if role != "data" {
			details = append(details, strings.TrimSuffix(role, "s")+" vdev")
		}
		errs := 0
		for _, c := range f[2:min(len(f), 5)] {
			n, _ := strconv.Atoi(c)
			errs += n
		}
		if errs > 0 {
			details = append(details, strconv.Itoa(errs)+" read/write/checksum errors")
			if d.Status == "ONLINE" {
				d.Status = "warning"
			}
		}
		d.Detail = strings.Join(details, ", ")
		pool.Disks = append(pool.Disks, d.Name)
	}
}

// parseMdstat: "md0 : active raid1 sdb1[1] sda1[0](F)", darunter "… blocks … [2/1] [U_]"
func parseMdstat(text string, byName map[string]*StorageDisk) []StoragePool {
	pools := []StoragePool{}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[0], "md") || f[1] != ":" {
			continue
		}
		p := StoragePool{Name: f[0], Kind: "RAID", Status: "online", Vdevs: []string{}, Disks: []string{}}
		if f[2] != "active" {
			p.Status = "offline"
		}
		var members []string
		for _, tok := range f[3:] { // "(auto-read-only)" und ähnliche Zusätze überspringen
			switch {
			case strings.HasPrefix(tok, "("):
			case len(p.Vdevs) == 0 && (strings.HasPrefix(tok, "raid") || tok == "linear"):
				p.Vdevs = append(p.Vdevs, strings.ToUpper(tok))
			default:
				members = append(members, tok)
			}
		}
		if i+1 < len(lines) {
			next := strings.Fields(lines[i+1])
			if len(next) > 1 && next[1] == "blocks" {
				blocks, _ := strconv.ParseInt(next[0], 10, 64)
				p.Size = blocks * 1024
			}
			if last := next[len(next)-1:]; len(last) == 1 && strings.HasPrefix(last[0], "[") && strings.Contains(last[0], "_") {
				p.Status = "degraded"
			}
		}
		for _, m := range members {
			dev := m
			if j := strings.Index(m, "["); j > 0 {
				dev = m[:j]
			}
			d := owner(dev, byName)
			if d == nil {
				continue
			}
			d.Pool, d.Status = p.Name, "online"
			if strings.HasSuffix(m, "(F)") {
				d.Status = "faulted"
			}
			p.Disks = append(p.Disks, d.Name)
		}
		pools = append(pools, p)
	}
	return pools
}

func smart(env Env, d *StorageDisk) {
	// Exit-Code ist eine Bitmaske (auch bei Erfolg ungleich 0): nur die Ausgabe zählt. -n standby weckt keine Platte.
	out, _ := env.Run("smartctl", "-j", "-H", "-A", "-n", "standby", "/dev/"+d.Name)
	var doc struct {
		SmartStatus *struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature *struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerMode string `json:"power_mode"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return
	}
	if doc.SmartStatus != nil {
		d.Smart = "FAILED"
		if doc.SmartStatus.Passed {
			d.Smart = "PASSED"
		}
	}
	if doc.Temperature != nil && doc.Temperature.Current > 0 {
		t := doc.Temperature.Current
		d.Temp = &t
	}
	if doc.SmartStatus == nil && strings.EqualFold(doc.PowerMode, "standby") {
		d.Detail = strings.TrimPrefix(d.Detail+", in standby, not woken", ", ")
	}
}
