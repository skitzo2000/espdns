package zonefiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

const homeZone = "$TTL 300\n@ IN SOA ns hostmaster ( 2026100301 3600 600 86400 300 )\n@ IN NS ns\nns IN A 192.0.2.10\nnas IN A 192.0.2.20\n"
const labZone = "$TTL 300\n@ IN SOA ns hostmaster 7 3600 600 86400 300\n@ IN NS ns\nns IN A 192.0.2.11\n"

func TestCheckName(t *testing.T) {
	for _, n := range []string{"home.example.zone", "2.0.192.in-addr.arpa.zone", "lan.zone", "a-b.c_d.zone"} {
		if err := CheckName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"", ".zone", "home.example", "../home.example.zone", "a/b.zone", "Home.example.zone", "a..b.zone",
		"-a.example.zone", "a-.example.zone", "a.-b.zone", "x.zone.prev", " a.zone", "a b.zone", "a.json", ".history.zone",
		strings.Repeat("a", 64) + ".zone", "a.zone/", "a.zone\x00"} {
		if CheckName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

// Save, history and delete: a zone the node would refuse is never saved; every version
// replaced or deleted is kept.
func TestSaveDelete(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, "home.example.zone", []byte("@ IN NS ns\n"), ""); err == nil || !strings.Contains(err.Error(), "SOA") {
		t.Errorf("no SOA saved: %v", err)
	}
	if _, err := Save(dir, "home.example.zone", []byte("@ IN SOA ns hostmaster 1 2 3 4 5\nx.other.example. IN A 192.0.2.1\n"), ""); err == nil {
		t.Error("a record outside the zone saved")
	}
	f, err := Save(dir, "home.example.zone", []byte(homeZone), "")
	if err != nil {
		t.Fatal(err)
	}
	if f.Zone != "home.example" || f.Serial != 2026100301 || f.Records != 4 || f.Error != "" || f.Mem == 0 {
		t.Fatalf("%+v", f)
	}
	if fi, _ := os.Stat(filepath.Join(Path(dir), "home.example.zone")); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	v2 := strings.Replace(homeZone, "2026100301", "2026100302", 1) + "www IN A 192.0.2.21\n"
	if _, err := Save(dir, "home.example.zone", []byte(v2), Hash([]byte("x"))); !errors.Is(err, ErrChanged) {
		t.Errorf("stale: %v", err)
	}
	f2, err := Save(dir, "home.example.zone", []byte(v2), f.Hash)
	if err != nil || f2.Records != 5 {
		t.Fatalf("%v %+v", err, f2)
	}
	if h, _ := History(dir, "home.example.zone"); len(h) != 1 {
		t.Errorf("history %v", h)
	}
	if err := Delete(dir, "home.example.zone", f.Hash); !errors.Is(err, ErrChanged) {
		t.Errorf("delete of an older version: %v", err)
	}
	if err := Delete(dir, "home.example.zone", f2.Hash); err != nil {
		t.Fatal(err)
	}
	if fs, _ := List(dir); len(fs) != 0 {
		t.Errorf("listed after delete: %v", fs)
	}
	del, _ := Deleted(dir)
	if v, ok := del["home.example.zone"]; !ok {
		t.Fatalf("deleted %v", del)
	} else if b, _ := ReadVersion(dir, "home.example.zone", v.File); string(b) != v2 {
		t.Errorf("kept %q", b)
	}
	if h, _ := History(dir, "home.example.zone"); len(h) != 2 {
		t.Errorf("history after delete %v", h)
	}
}

func stat(t *testing.T, s string) *release.NodeStatus {
	t.Helper()
	var st release.NodeStatus
	if err := json.Unmarshal([]byte(s), &st); err != nil {
		t.Fatal(err)
	}
	return &st
}

// Which nodes serve a zone, and whether it is the file as saved: by the record of the set
// pushed while the node's hosted seq is the one recorded, else by serial only.
func TestServes(t *testing.T) {
	dir := t.TempDir()
	f, _ := Save(dir, "home.example.zone", []byte(homeZone), "")
	st := stat(t, `{"node_id":"02:00:00:00:00:21","hosted":{"state":"on","seq":5,"zones":[{"name":"home.example","serial":2026100301,"records":4}]}}`)
	if s, ok := Serves(dir, f, "n", *st, MatchUnknown); !ok || s.State != "unrecorded" || !strings.Contains(s.Text, "as the file") {
		t.Errorf("unrecorded: %v %+v", ok, s)
	}
	RecordPushed(dir, Pushed{NodeID: "02:00:00:00:00:21", Seq: 5, Files: map[string]string{"home.example.zone": f.Hash}, By: "controller"})
	if s, ok := Serves(dir, f, "n", *st, MatchUnknown); !ok || s.State != "file" {
		t.Errorf("file: %+v", s)
	}
	f2, _ := Save(dir, "home.example.zone", []byte(strings.Replace(homeZone, "2026100301", "2026100302", 1)), f.Hash)
	if s, _ := Serves(dir, f2, "n", *st, MatchUnknown); s.State != "other" {
		t.Errorf("other: %+v", s)
	}
	st.Hosted.Seq = 6 // pushed since by something that left no record
	if s, _ := Serves(dir, f2, "n", *st, MatchUnknown); s.State != "unrecorded" || !strings.Contains(s.Text, "the file has serial 2026100302") {
		t.Errorf("another seq: %+v", s)
	}
	lab, _ := Save(dir, "lab.example.zone", []byte(labZone), "")
	if _, ok := Serves(dir, lab, "n", *st, MatchUnknown); ok {
		t.Error("serves a zone it doesn't")
	}
	if _, ok := Serves(dir, lab, "n", release.NodeStatus{}, MatchUnknown); ok {
		t.Error("old firmware serves it")
	}
	if err := RecordPushed(dir, Pushed{NodeID: "../../x"}); err == nil {
		t.Error("a node ID that's a path")
	}
}

// A node's whole set compared by the bundle hash it reports: the same bytes as the files
// here say "serves it" with no record; the same serial and records with other content (a
// file pushed from elsewhere) is not taken for the file.
func TestSetMatch(t *testing.T) {
	dir := t.TempDir()
	f, _ := Save(dir, "home.example.zone", []byte(homeZone), "")
	files, _ := List(dir)
	b, err := (&zones.Set{Zones: []*zones.Zone{f.Parsed}}).Bundle(0)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	js := func(sha string) release.NodeStatus {
		return *stat(t, `{"node_id":"02:00:00:00:00:21","hosted":{"state":"on","seq":9,"sha256":"`+sha+
			`","zones":[{"name":"home.example","serial":`+fmt.Sprint(f.Serial)+`,"records":`+fmt.Sprint(f.Records)+`}]}}`)
	}
	st := js(hex.EncodeToString(sum[:]))
	if m := SetMatch(files, st); m != MatchFiles {
		t.Fatalf("match %v", m)
	}
	if s, _ := Serves(dir, f, "n", st, MatchFiles); s.State != "file" {
		t.Errorf("by hash: %+v", s)
	}
	other := js(strings.Repeat("ab", 32)) // same serial and records, other bytes
	if m := SetMatch(files, other); m != MatchNot {
		t.Fatalf("no match %v", m)
	}
	if s, _ := Serves(dir, f, "n", other, MatchNot); s.State != "other" {
		t.Errorf("other bytes, same serial: %+v", s)
	}
	if m := SetMatch(files, js("")); m != MatchUnknown {
		t.Errorf("no hash: %v", m)
	}
	if m := SetMatch(nil, st); m != MatchUnknown {
		t.Errorf("no file: %v", m)
	}
	// A push's record is by zone, wherever the file was read from.
	read := func(string) ([]byte, error) { return []byte(homeZone), nil }
	got, err := PushedFiles([]string{"/elsewhere/home.example.zone", "Lab.Example.=/tmp/x.txt"}, read)
	if err != nil || len(got) != 2 || got["home.example.zone"] != f.Hash || got["lab.example.zone"] != f.Hash {
		t.Errorf("pushed files %v %v", got, err)
	}
}

// The editor's check: espdns zones -check on the zone, then for each node the set it would
// get from here, refused as a push to it would be.
func TestCheckNodes(t *testing.T) {
	dir := t.TempDir()
	Save(dir, "lab.example.zone", []byte(labZone), "")
	saved, _ := Save(dir, "home.example.zone", []byte(homeZone), "")
	// The config pushed to "n4" (still its seq): home.example is a forward zone there. A
	// config file "n8" (by name) has it too, but none was recorded as pushed to n8: not read.
	n4cfg := `{"name":"n4","forward_zones":[{"zone":"home.example","forwarder":"198.51.100.1"}]}`
	configs.Save(dir, "n4.json", []byte(n4cfg), "")
	configs.RecordPushed(dir, configs.Pushed{NodeID: "02:00:00:00:00:04", Host: "n4", File: "n4.json", Seq: 2, Payload: json.RawMessage(n4cfg)})
	configs.Save(dir, "n8.json", []byte(strings.ReplaceAll(n4cfg, "n4", "n8")), "")
	hosted := func(limit int) string {
		return `"hosted":{"state":"on","seq":3,"limit_bytes":` + itoa(limit) + `,"zones":[{"name":"home.example","serial":2026100305,"records":4},` +
			`{"name":"lab.example","serial":7,"records":3},{"name":"gone.example","serial":1,"records":2}]}`
	}
	ns := []Node{
		{Host: "n1", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:01",`+hosted(64<<10)+`}`)},
		{Host: "n2", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:02",`+hosted(1024)+`}`)},
		{Host: "n3", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:03",`+hosted(64<<10)+`,"zones":[{"name":"home.example."}]}`)},
		{Host: "n4", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:04","config":{"source":"node","seq":2,"name":"n4"},`+hosted(64<<10)+`}`)},
		{Host: "n5", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:05",`+hosted(64<<10)+`,"services":[{"name":"hosted","state":"off"}]}`)},
		{Host: "n6", Listed: false, Status: stat(t, `{"node_id":"02:00:00:00:00:06"}`)},
		{Host: "n7", Listed: false},
		{Host: "n8", Listed: true, Status: stat(t, `{"node_id":"02:00:00:00:00:08","config":{"source":"node","seq":5,"name":"n8"},`+hosted(64<<10)+`,"forward_zones":[]}`)},
	}
	edited := strings.Replace(homeZone, "nas IN", "files IN", 1)
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	r := Check{DataDir: dir, Name: "home.example.zone", Text: []byte(edited), Saved: &saved, Nodes: ns, Now: now}.Run(context.Background())
	if r.Error != "" || r.OK || r.Command != "espdns zones -zone home.example.zone -check" || len(r.Lines) != 2 ||
		r.Lines[0] != "home.example: serial 2026100301, 4 records" || r.Records != 4 || len(r.List) != 4 || len(r.Diff) == 0 {
		t.Fatalf("%+v", r)
	}
	// The serial: not raised above the saved file's, nor above what the nodes serve.
	if !strings.Contains(r.SerialWarn, "2026100305") || r.NextSerial != 2026100306 {
		t.Errorf("serial: %q %d", r.SerialWarn, r.NextSerial)
	}
	want := map[string]string{
		"n1": "",
		"n2": "hosted_zones_kb",
		"n3": "a secondary zone of n3",
		"n4": "secondary or forward zone in the node config (n4.json, as pushed to it (config seq 2))",
		"n5": "hosted is off",
		"n6": "update its firmware",
		"n7": "no /status",
	}
	for _, n := range r.Nodes {
		w := want[n.Host]
		if w == "" && n.Refused != "" || w != "" && !strings.Contains(n.Refused, w) {
			t.Errorf("%s: refused %q, want %q", n.Host, n.Refused, w)
		}
	}
	n1 := r.Nodes[0]
	if !n1.Serves || n1.Serial != 2026100305 || strings.Join(n1.Set, ",") != "home.example.zone,lab.example.zone" ||
		strings.Join(n1.Missing, ",") != "gone.example" || n1.Bytes == 0 || n1.LimitKB != 64 || len(n1.Lines) != 3 {
		t.Errorf("n1: %+v", n1)
	}
	// A zone that doesn't pass: the CLI's error, nothing against the nodes.
	r = Check{DataDir: dir, Name: "home.example.zone", Text: []byte("@ IN NS ns\n"), Nodes: ns}.Run(context.Background())
	if r.OK || !strings.Contains(r.Error, "SOA") || len(r.Nodes) != 0 {
		t.Errorf("bad: %+v", r)
	}
	// A new zone: no serial warning.
	r = Check{DataDir: dir, Name: "new.example.zone", Text: []byte(labZone), Now: now}.Run(context.Background())
	if !r.OK || r.SerialWarn != "" || r.NextSerial != 8 {
		t.Errorf("new: %+v", r)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
