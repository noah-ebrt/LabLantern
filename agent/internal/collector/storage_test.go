package collector

import (
	"errors"
	"reflect"
	"testing"
)

const lsblkOut = `{"blockdevices": [
 {"name":"sda","model":"WDC WD40EFRX-68N ","serial":"WD-1","size":4000787030016,"rota":true,"tran":"sata","type":"disk"},
 {"name":"sdb","model":"WDC WD40EFRX-68N","serial":"WD-2","size":"4000787030016","rota":"1","tran":"sata","type":"disk"},
 {"name":"sdc","model":"WDC WD40EFRX-68N","serial":"WD-3","size":4000787030016,"rota":true,"tran":"sata","type":"disk"},
 {"name":"nvme0n1","model":"Samsung SSD 990 PRO","serial":"S1","size":1000204886016,"rota":false,"tran":"nvme","type":"disk"},
 {"name":"sdd","model":"Crucial MX500","serial":"C1","size":250059350016,"rota":false,"tran":"sata","type":"disk"},
 {"name":"sde","model":"Crucial MX500","serial":"C2","size":250059350016,"rota":"0","tran":"sata","type":"disk"},
 {"name":"zram0","size":1000,"rota":false,"type":"disk"},
 {"name":"sr0","model":"DVD","size":1000,"rota":true,"type":"rom"}]}`

const zpoolStatus = "  pool: tank\n state: DEGRADED\nconfig:\n\n" +
	"\tNAME                  STATE     READ WRITE CKSUM\n" +
	"\ttank                  DEGRADED     0     0     0\n" +
	"\t  raidz1-0            DEGRADED     0     0     0\n" +
	"\t    /dev/sda1         ONLINE       0     0     0\n" +
	"\t    /dev/sdb1         ONLINE       3     0     1\n" +
	"\t    /dev/sdc1         FAULTED      0     0     0\n" +
	"\tcache\n" +
	"\t  /dev/nvme0n1p1      ONLINE       0     0     0\n\n" +
	"errors: No known data errors\n"

const mdstat = "Personalities : [raid1]\n" +
	"md0 : active (auto-read-only) raid1 sde1[1](F) sdd1[0]\n" +
	"      244066304 blocks super 1.2 [2/1] [U_]\n\nunused devices: <none>\n"

func storageFake() *fake {
	f := newFake()
	f.bins["lsblk"], f.bins["zpool"], f.bins["smartctl"] = true, true, true
	f.cmds["systemd-detect-virt"] = result{"none\n", errors.New("exit status 1")}
	f.cmds["lsblk"] = result{out: lsblkOut}
	f.cmds["zpool list -H -p -o name,size,alloc,health"] = result{out: "tank\t12000\t4800\tDEGRADED\n"}
	f.cmds["zpool status -P -L"] = result{out: zpoolStatus}
	f.cmds["smartctl -j -H -A -n standby /dev/sda"] = result{`{"smart_status":{"passed":true},"temperature":{"current":34}}`, errors.New("exit status 4")}
	f.cmds["smartctl -j -H -A -n standby /dev/sdc"] = result{`{"smart_status":{"passed":false}}`, errors.New("exit status 8")}
	f.cmds["smartctl -j -H -A -n standby /dev/sdb"] = result{`{"power_mode":"STANDBY"}`, errors.New("exit status 2")}
	f.cmds["smartctl"] = result{out: "", err: errors.New("exit status 2")} // übrige Laufwerke: keine Angaben
	f.files["/proc/mdstat"] = mdstat
	return f
}

func TestStorageZfsMdraidAndSmart(t *testing.T) {
	r := &HostReport{CollectionErrors: map[string]string{}}
	collectStorage(storageFake().env(), r)
	st := r.Storage
	if st == nil || st.Error != "" {
		t.Fatalf("Speicher fehlt oder Fehler: %+v", st)
	}
	if len(st.Disks) != 6 {
		t.Fatalf("zram und sr0 gehören nicht dazu: %d Laufwerke", len(st.Disks))
	}
	disks := map[string]StorageDisk{}
	for _, d := range st.Disks {
		disks[d.Name] = d
	}
	if d := disks["sda"]; d.Pool != "tank" || d.Status != "ONLINE" || d.Smart != "PASSED" || d.Temp == nil || *d.Temp != 34 || d.Model != "WDC WD40EFRX-68N" {
		t.Errorf("sda: %+v", d)
	}
	if d := disks["sdb"]; d.Status != "warning" || d.Detail != "4 read/write/checksum errors, in standby, not woken" || d.Smart != "" || d.Size != 4000787030016 {
		t.Errorf("sdb: %+v", d)
	}
	if d := disks["sdc"]; d.Status != "FAULTED" || d.Smart != "FAILED" {
		t.Errorf("sdc: %+v", d)
	}
	if d := disks["nvme0n1"]; d.Type != "nvme" || d.Pool != "tank" || d.Detail != "cache vdev" {
		t.Errorf("nvme0n1: %+v", d)
	}
	if d := disks["sde"]; d.Type != "ssd" || d.Pool != "md0" || d.Status != "faulted" {
		t.Errorf("sde: %+v", d)
	}
	if len(st.Pools) != 2 {
		t.Fatalf("Pools: %+v", st.Pools)
	}
	tank, md := st.Pools[0], st.Pools[1]
	if tank.Status != "DEGRADED" || tank.Size != 12000 || tank.Alloc != 4800 || !reflect.DeepEqual(tank.Vdevs, []string{"RAIDZ1"}) ||
		!reflect.DeepEqual(tank.Disks, []string{"sda", "sdb", "sdc", "nvme0n1"}) {
		t.Errorf("tank: %+v", tank)
	}
	if md.Status != "degraded" || !reflect.DeepEqual(md.Vdevs, []string{"RAID1"}) || md.Size != 244066304*1024 ||
		!reflect.DeepEqual(md.Disks, []string{"sde", "sdd"}) {
		t.Errorf("md0: %+v", md)
	}
}

func TestStorageStripeAndMirror(t *testing.T) {
	pools := map[string]*StoragePool{"a": {Name: "a"}, "b": {Name: "b"}}
	byName := map[string]*StorageDisk{"sda": {Name: "sda"}, "sdb": {Name: "sdb"}, "sdc": {Name: "sdc"}, "sdd": {Name: "sdd"}}
	parseZpoolStatus("  pool: a\nconfig:\n\tNAME STATE READ WRITE CKSUM\n\ta ONLINE 0 0 0\n\t  /dev/sda ONLINE 0 0 0\n\t  /dev/sdb ONLINE 0 0 0\nerrors: none\n"+
		"  pool: b\nconfig:\n\tb ONLINE 0 0 0\n\t  mirror-0 ONLINE 0 0 0\n\t    /dev/sdc2 ONLINE 0 0 0\n\t    /dev/sdd2 ONLINE 0 0 0\n", pools, byName)
	if !reflect.DeepEqual(pools["a"].Vdevs, []string{"STRIPE", "STRIPE"}) || !reflect.DeepEqual(pools["b"].Vdevs, []string{"MIRROR"}) {
		t.Errorf("Aufbau: a=%v b=%v", pools["a"].Vdevs, pools["b"].Vdevs)
	}
	if byName["sdc"].Pool != "b" || byName["sda"].Pool != "a" {
		t.Errorf("Zuordnung: %+v %+v", byName["sdc"], byName["sda"])
	}
}

func TestNoStorageInVmOrContainer(t *testing.T) {
	f := storageFake()
	f.cmds["systemd-detect-virt"] = result{out: "kvm\n"}
	r := &HostReport{}
	collectStorage(f.env(), r)
	if r.Storage != nil {
		t.Errorf("VM: kein Speicher erwartet, %+v", r.Storage)
	}
	f = storageFake()
	f.exists["/run/systemd/container"] = true
	collectStorage(f.env(), r)
	if r.Storage != nil {
		t.Errorf("LXC: kein Speicher erwartet")
	}
}
