package recovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

const zoneText = `$ORIGIN home.example.
$TTL 300
@ IN SOA ns.home.example. admin.home.example. 2026100301 3600 600 86400 300
@ IN NS ns.home.example.
ns IN A 192.0.2.10
`

// node serves /status (st) and /health as a node does; it counts the requests that are not
// a GET (and answers them 405).
func node(t *testing.T, st map[string]any, changes *atomic.Int32) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			changes.Add(1)
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(st)
		case "/health":
			json.NewEncoder(w).Encode(map[string]any{"state": "healthy", "answering": true, "reasons": []string{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func status(id, fp, cfgName string, source string, hosted map[string]any) map[string]any {
	return map[string]any{"node_id": id, "board": "p4-ip101", "image": "esp32p4-rev1", "version": "v3",
		"keys": []string{fp, "1111"}, "seq": map[string]uint64{"config": 1_790_000_000_000, "firmware": 1_780_000_000_000},
		"config":   map[string]any{"source": source, "seq": 1_790_000_000_000, "name": cfgName, "address": "static", "ip": "203.0.113.51/24"},
		"zones":    []map[string]any{{"name": "home.example"}},
		"hosted":   hosted,
		"blocking": map[string]any{"list": map[string]any{"state": "on", "seq": 7, "entries": 1234}}}
}

// bundleHash is the hash of the bundle a node runs with the zone file's text.
func bundleHash(t *testing.T, text string) string {
	z, err := zonefiles.Parse("home.example.zone", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&zones.Set{Zones: []*zones.Zone{z}}).Bundle(0)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestRecover(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := keys.FileSource{Path: keys.Path(dir)}
	c := &fleet.Client{}
	// No key: refused, before any node is read.
	if _, err := Run(context.Background(), c, Options{DataDir: dir, Key: key}); err == nil || !strings.Contains(err.Error(), "import it first") {
		t.Fatalf("no key: %v", err)
	}
	if _, err := keys.Import(keys.Path(dir), k, false); err != nil {
		t.Fatal(err)
	}
	fp, ofp := keys.Fingerprint(k), keys.Fingerprint(other)
	// The zone file here is the one dns2 serves; dns3 serves another version of it.
	os.MkdirAll(zonefiles.Path(dir), 0o700)
	os.WriteFile(filepath.Join(zonefiles.Path(dir), "home.example.zone"), []byte(zoneText), 0o600)
	os.MkdirAll(filepath.Join(dir, "configs"), 0o700)
	os.WriteFile(filepath.Join(dir, "configs/dns2.json"), []byte(`{"name": "dns2"}`), 0o600)
	var changes atomic.Int32
	hz := func(serial int, hash string) map[string]any {
		return map[string]any{"state": "on", "seq": 9, "sha256": hash,
			"zones": []map[string]any{{"name": "home.example", "serial": serial, "records": 3}}}
	}
	a := node(t, status("02:00:00:00:00:51", fp, "dns2", "node", hz(2026100301, bundleHash(t, zoneText))), &changes)
	b := node(t, status("02:00:00:00:00:52", fp, "dns3", "node", hz(2026100302, strings.Repeat("ab", 32))), &changes)
	foreign := node(t, status("02:00:00:00:00:53", ofp, "x", "node", nil), &changes)
	fresh := node(t, status("02:00:00:00:00:54", fp, "", "defaults", nil), &changes)
	hosts := []string{a, b, foreign, fresh, "127.0.0.1:1"}
	now := func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }

	// A dry run reads and writes nothing.
	r, err := Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key, DryRun: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settings.Path(dir)); !errors.Is(err, os.ErrNotExist) || r.Dir != "" || !strings.HasPrefix(r.Settings, "dry run") {
		t.Fatalf("dry run wrote: %v %+v", err, r)
	}
	if _, err := os.Stat(filepath.Join(dir, Dir)); err == nil {
		t.Fatal("dry run made recovered/")
	}
	if _, err := os.Stat(filepath.Join(dir, pins.Dir)); err == nil {
		t.Fatal("dry run pinned nodes")
	}

	r, err = Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// settings.json: the two nodes in service that trust the key, not the one that doesn't,
	// not the one not adopted, not the address that doesn't answer.
	s, err := settings.Load(settings.Path(dir))
	if err != nil || !slices.Equal(s.Nodes, sorted(a, b)) || len(s.DNSPeers) != 0 {
		t.Fatalf("settings %+v %v", s, err)
	}
	by := map[string]Node{}
	for _, n := range r.Nodes {
		by[n.Addr] = n
	}
	if n := by[a]; !n.Listed || !slices.Equal(n.ConfigFiles, []string{"dns2.json"}) || n.Hosted[0].File != "the node's bundle" ||
		!strings.Contains(strings.Join(n.Notes, "\n"), "byte for byte") || n.Lists["blocklist"].Entries != 1234 {
		t.Errorf("dns2: %+v", n)
	}
	if n := by[b]; n.ConfigFiles != nil || n.Hosted[0].File != "a file, not the one it serves" ||
		!strings.Contains(strings.Join(n.Notes, "\n"), `runs config "dns3"`) {
		t.Errorf("dns3: %+v", n)
	}
	if n := by[foreign]; n.Trusts || n.Listed || !strings.Contains(strings.Join(n.Notes, "\n"), "doesn't trust") {
		t.Errorf("foreign: %+v", n)
	}
	if n := by[fresh]; n.Adopted || n.Listed {
		t.Errorf("not adopted: %+v", n)
	}
	if n := by["127.0.0.1:1"]; n.Error == "" {
		t.Errorf("no node: %+v", n)
	}
	// The nodes listed are pinned to their addresses, as adopting them did; no other.
	l := pins.Open(dir)
	for h, id := range map[string]string{a: "02:00:00:00:00:51", b: "02:00:00:00:00:52", foreign: "", fresh: ""} {
		got, err := l.Pinned(h)
		if got != id || (id == "") != errors.Is(err, pins.ErrNotPinned) || by[h].Pinned != (id != "") {
			t.Errorf("%s pinned to %q (%v), reported %v", h, got, err, by[h].Pinned)
		}
	}
	// One pinned to another node here already (a board replaced since) is left so, and said.
	if _, err := l.Pin("02:00:00:00:00:99", b); err != nil {
		t.Fatal(err)
	}
	// recovered/<time>/: each node's /status and the report, 0600.
	want := filepath.Join(dir, Dir, "20261003-120000")
	if r.Dir != want {
		t.Errorf("dir %q", r.Dir)
	}
	var rep Report
	if b, err := os.ReadFile(filepath.Join(want, "report.json")); err != nil || json.Unmarshal(b, &rep) != nil || len(rep.Nodes) != 5 {
		t.Errorf("report: %v %+v", err, rep)
	}
	ents, _ := os.ReadDir(want)
	if len(ents) != 5 { // four statuses and the report
		t.Errorf("recovered: %v", ents)
	}
	var st release.NodeStatus
	if b, err := os.ReadFile(filepath.Join(want, "status-"+strings.ReplaceAll(a, ":", "_")+".json")); err != nil || json.Unmarshal(b, &st) != nil ||
		st.NodeID != "02:00:00:00:00:51" {
		t.Errorf("status of dns2: %v %+v", err, st)
	}
	// The nodes were only read.
	if n := changes.Load(); n != 0 {
		t.Errorf("%d requests to the nodes not a GET", n)
	}

	// Again, with settings.json there now listing one: not changed unless asked.
	settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{a}, DNSPeers: []string{"203.0.113.254"}})
	later := func() time.Time { return now().Add(time.Minute) }
	r, err = Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key, Now: later})
	if err != nil || !strings.Contains(r.Settings, "-add-to-settings") {
		t.Fatalf("%v %s", err, r.Settings)
	}
	if s, _ := settings.Load(settings.Path(dir)); !slices.Equal(s.Nodes, []string{a}) {
		t.Errorf("changed unasked: %+v", s)
	}
	r, err = Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key, AddToSettings: true,
		Now: func() time.Time { return now().Add(2 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := settings.Load(settings.Path(dir)); !slices.Equal(s.Nodes, []string{a, b}) || !slices.Equal(s.DNSPeers, []string{"203.0.113.254"}) {
		t.Errorf("added: %+v", s)
	}
	for _, n := range r.Nodes {
		if n.Addr == b && (n.Pinned || !strings.Contains(strings.Join(n.Notes, "\n"), "02:00:00:00:00:99 is pinned to")) {
			t.Errorf("pinned to another node: %+v", n)
		}
	}
	if id, _ := l.Pinned(b); id != "02:00:00:00:00:99" {
		t.Errorf("the pin there changed: %q", id)
	}
	// Never over a recovered directory there (the same second).
	if _, err := Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key, Now: later}); err == nil {
		t.Error("wrote over recovered/ of the same time")
	}
	// Under a held fleet lock: refused, naming the holder.
	lk, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("espdns rollout", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	if _, err := Run(context.Background(), c, Options{DataDir: dir, Hosts: hosts, Key: key,
		Now: func() time.Time { return now().Add(time.Hour) }}); !errors.Is(err, fleetlock.ErrLocked) {
		t.Errorf("locked: %v", err)
	}
}

// A node ID answering at two addresses (a host copying a node's /status, its key's
// fingerprint and all): neither is added to settings.json, and both say why.
func TestRecoverSameIDTwice(t *testing.T) {
	dir := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := keys.Import(keys.Path(dir), k, false); err != nil {
		t.Fatal(err)
	}
	fp := keys.Fingerprint(k)
	var changes atomic.Int32
	real := node(t, status("02:00:00:00:00:51", fp, "dns2", "node", nil), &changes)
	copied := node(t, status("02:00:00:00:00:51", fp, "dns2", "node", nil), &changes)
	other := node(t, status("02:00:00:00:00:52", fp, "dns3", "node", nil), &changes)
	r, err := Run(context.Background(), &fleet.Client{}, Options{DataDir: dir, Hosts: []string{real, copied, other},
		Key: keys.FileSource{Path: keys.Path(dir)}})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := settings.Load(settings.Path(dir)); err != nil || !slices.Equal(s.Nodes, []string{other}) {
		t.Fatalf("settings %+v %v", s, err)
	}
	for _, n := range r.Nodes {
		twice := strings.Contains(strings.Join(n.Notes, "\n"), "isn't this node")
		if twice != (n.Addr != other) || n.Listed != (n.Addr == other) || n.Pinned != (n.Addr == other) {
			t.Errorf("%s: %+v", n.Addr, n)
		}
	}
}

func sorted(s ...string) []string {
	slices.Sort(s)
	return s
}
