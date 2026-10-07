package configs

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

func TestCheckName(t *testing.T) {
	for _, n := range []string{"dns2.json", "a.json", "node-1_b.v2.json"} {
		if err := CheckName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"", "dns2", "../dns2.json", "a/b.json", "Dns2.json", ".x.json", "fleet.json", "settings.json",
		"a..json", "x.json.prev", " a.json", "a b.json"} {
		if CheckName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A save: checked first, whole, 0600, only over the version it was made from, the one it
// replaces kept in the history (the newest HistoryKeep).
func TestSave(t *testing.T) {
	dir := t.TempDir()
	v1 := []byte("{\n  \"name\": \"a\"\n}\n")
	f, err := Save(dir, "a.json", v1, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(Path(dir), "a.json")
	if mode(t, p) != 0o600 || f.Hash != Hash(v1) || f.Config == nil || f.Config.Name != "a" {
		t.Fatalf("%+v %v", f, mode(t, p))
	}
	if _, err := Save(dir, "a.json", v1, ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("a new file over one: %v", err)
	}
	if _, err := Save(dir, "a.json", v1, Hash([]byte("other"))); !errors.Is(err, ErrChanged) {
		t.Errorf("a stale hash: %v", err)
	}
	if _, err := Save(dir, "gone.json", v1, Hash(v1)); !errors.Is(err, ErrChanged) {
		t.Errorf("a file that is gone: %v", err)
	}
	// Refused as the node refuses it: nothing written, the file as it was.
	for _, bad := range []string{`{"fowarders":[]}`, `{"network":{"address":"203.0.113.5"}}`, `not json`, `{"name":"a"} {}`} {
		if _, err := Save(dir, "a.json", []byte(bad), f.Hash); err == nil {
			t.Errorf("%s saved", bad)
		}
	}
	if b, _ := os.ReadFile(p); string(b) != string(v1) {
		t.Fatalf("after refused saves: %s", b)
	}
	if _, err := Save(dir, "../x.json", v1, ""); err == nil {
		t.Error("a name outside the directory")
	}
	// Saved over the right version: the old one in the history.
	v2 := []byte(`{"name":"a","forwarders":["9.9.9.9"]}`)
	f2, err := Save(dir, "a.json", v2, f.Hash)
	if err != nil {
		t.Fatal(err)
	}
	h, err := History(dir, "a.json")
	if err != nil || len(h) != 1 {
		t.Fatalf("history %v %v", h, err)
	}
	hp := filepath.Join(Path(dir), HistoryDir, h[0].File)
	if b, _ := os.ReadFile(hp); string(b) != string(v1) || mode(t, hp) != 0o600 {
		t.Errorf("kept %s, mode %v", b, mode(t, hp))
	}
	// No temporary file left behind.
	ents, _ := os.ReadDir(Path(dir))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp") {
			t.Errorf("left %s", e.Name())
		}
	}
	// The newest HistoryKeep are kept, newest first.
	last := f2.Hash
	for i := range HistoryKeep + 3 {
		b, _ := json.Marshal(map[string]any{"name": "a", "upstream_timeout_ms": 100 + i})
		g, err := Save(dir, "a.json", b, last)
		if err != nil {
			t.Fatal(err)
		}
		last = g.Hash
	}
	h, _ = History(dir, "a.json")
	if len(h) != HistoryKeep || !h[0].Time.After(h[len(h)-1].Time) {
		t.Fatalf("%d kept: %v", len(h), h)
	}
	if b, _ := os.ReadFile(filepath.Join(Path(dir), HistoryDir, h[0].File)); !strings.Contains(string(b), `"upstream_timeout_ms":121`) {
		t.Errorf("newest kept: %s", b)
	}
	// Another config's history is its own.
	if hb, _ := History(dir, "b.json"); len(hb) != 0 {
		t.Errorf("b.json: %v", hb)
	}
	// A link isn't replaced by a save.
	os.WriteFile(filepath.Join(dir, "real.json"), v1, 0o600)
	os.Symlink(filepath.Join(dir, "real.json"), filepath.Join(Path(dir), "l.json"))
	if _, err := Save(dir, "l.json", v2, Hash(v1)); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("over a link: %v", err)
	}
	// List: by name, the bad one with its error.
	os.WriteFile(filepath.Join(Path(dir), "bad.json"), []byte(`{"x":1}`), 0o600)
	os.WriteFile(filepath.Join(Path(dir), "notes.txt"), []byte(`x`), 0o600)
	fs, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range fs {
		names = append(names, f.Name)
		if f.Name == "bad.json" && !strings.Contains(f.Error, "unknown field") {
			t.Errorf("bad.json: %q", f.Error)
		}
	}
	if !slices.Equal(names, []string{"a.json", "bad.json", "l.json"}) {
		t.Errorf("list %v", names)
	}
}

func TestResolve(t *testing.T) {
	dir := t.TempDir()
	Save(dir, "a.json", []byte(`{}`), "")
	if got := Resolve(dir, "a.json"); got != filepath.Join(Path(dir), "a.json") {
		t.Errorf("a.json: %s", got)
	}
	for _, p := range []string{"b.json", "./a.json", "/fleet/configs/a.json", "x/a.json"} {
		if got := Resolve(dir, p); got != p {
			t.Errorf("%s: %s", p, got)
		}
	}
}

const withPass = `{
  "name": "w",
  "wifi": { "ssid": "home", "password": "s3cret \"pw\"!", "tx_power_dbm": 11 },
  "forwarders": [ "9.9.9.9" ]
}
`

// The password never shows; a text that still has the stand-in keeps the saved one.
func TestMask(t *testing.T) {
	m, ok := Mask([]byte(withPass))
	if !ok || strings.Contains(string(m), "s3cret") || !strings.Contains(string(m), `"password": "`+Hidden+`"`) {
		t.Fatalf("%v %s", ok, m)
	}
	if strings.Replace(string(m), `"`+Hidden+`"`, `"s3cret \"pw\"!"`, 1) != withPass {
		t.Errorf("the rest changed:\n%s", m)
	}
	back, err := Unmask(m, []byte(withPass))
	if err != nil || string(back) != withPass {
		t.Fatalf("%v\n%s", err, back)
	}
	// Edited around it: the password kept, the edit too.
	ed := strings.Replace(string(m), "9.9.9.9", "1.1.1.1", 1)
	back, _ = Unmask([]byte(ed), []byte(withPass))
	if !strings.Contains(string(back), `"s3cret \"pw\"!"`) || !strings.Contains(string(back), "1.1.1.1") {
		t.Errorf("%s", back)
	}
	// A new password typed: that one.
	ed = strings.Replace(string(m), Hidden, "newpassword", 1)
	if back, _ = Unmask([]byte(ed), []byte(withPass)); !strings.Contains(string(back), `"newpassword"`) {
		t.Errorf("%s", back)
	}
	// The stand-in with nothing saved to put back.
	if _, err := Unmask(m, nil); !errors.Is(err, ErrHiddenPassword) {
		t.Errorf("no saved: %v", err)
	}
	if _, err := Unmask(m, []byte(`{"wifi":{"ssid":"x","password":""}}`)); !errors.Is(err, ErrHiddenPassword) {
		t.Errorf("saved open: %v", err)
	}
	// An open network stays open; no wifi, nothing to mask.
	if m, ok := Mask([]byte(`{"wifi":{"ssid":"x","password":""}}`)); !ok || !strings.Contains(string(m), `"password":""`) {
		t.Errorf("%s", m)
	}
	if _, ok := Mask([]byte(`{"name":"password","time":{"tz":"UTC0"}}`)); ok {
		t.Error("masked without a password")
	}
	// Text that isn't JSON (mid-edit) is masked anyway.
	if m, _ := Mask([]byte(`{"wifi":{"ssid":"x","password":"hunter22",`)); strings.Contains(string(m), "hunter22") {
		t.Errorf("broken JSON: %s", m)
	}
	// A password-shaped value elsewhere isn't the password.
	if m, _ := Mask([]byte(`{"wifi":{"ssid":"password","password":"hunter22"}}`)); !strings.Contains(string(m), `"ssid":"password"`) ||
		strings.Contains(string(m), "hunter22") {
		t.Errorf("%s", m)
	}
	// The payload, compact, masks too.
	c, _ := nodecfg.Parse([]byte(withPass))
	p, _ := c.Payload()
	if m, _ := Mask(p); strings.Contains(string(m), "s3cret") {
		t.Errorf("payload %s", m)
	}
}

func TestDiff(t *testing.T) {
	if Diff([]byte("a\nb\n"), []byte("a\nb\n")) != nil {
		t.Error("same texts")
	}
	d := Diff([]byte("a\nb\nc\n"), []byte("a\nB\nc\nd\n"))
	var got []string
	for _, l := range d {
		got = append(got, l.Op+l.Text)
	}
	if want := []string{" a", "-b", "+B", " c", "+d"}; !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
	if d[1].Old != 2 || d[2].New != 2 || d[4].New != 4 {
		t.Errorf("%+v", d)
	}
}

func TestPushed(t *testing.T) {
	dir := t.TempDir()
	if p, err := LoadPushed(dir, "30:ed:a0:00:00:01"); p != nil || err != nil {
		t.Fatal(p, err)
	}
	if err := RecordPushed(dir, Pushed{NodeID: "../x"}); err == nil {
		t.Error("a bad node ID")
	}
	if err := RecordPushed(dir, Pushed{NodeID: "30:ED:A0:00:00:01", Host: "h", File: "a.json", Seq: 7, Payload: []byte(`{"format":1}`)}); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPushed(dir, "30:ed:a0:00:00:01")
	if err != nil || p.Seq != 7 || p.File != "a.json" || string(p.Payload) != `{"format":1}` {
		t.Fatalf("%+v %v", p, err)
	}
	if m := mode(t, filepath.Join(Path(dir), PushedDir, "30eda0000001.json")); m != 0o600 {
		t.Errorf("mode %v", m)
	}
}

func status(source string, seq uint64, name string) release.NodeStatus {
	return release.NodeStatus{NodeID: "30:ed:a0:00:00:01", Config: &release.ConfigStatus{Source: source, Seq: seq, Name: name,
		Address: "static", IP: "192.0.2.252/23", Gateway: "192.0.2.1", AddressFrom: "config"}}
}

// What a node runs, against a file: recorded pushes by seq.
func TestNodeRuns(t *testing.T) {
	dir := t.TempDir()
	f, _ := Save(dir, "a.json", []byte(`{"name":"a","forwarders":["9.9.9.9"]}`), "")
	if r := NodeRuns(dir, "a.json", &f, release.NodeStatus{}); r.State != "unknown" {
		t.Errorf("no config: %+v", r)
	}
	if r := NodeRuns(dir, "a.json", &f, status("defaults", 0, "")); r.State != "defaults" || r.Config == nil {
		t.Errorf("defaults: %+v", r)
	}
	if r := NodeRuns(dir, "a.json", &f, status("node", 5, "a")); r.State != "unrecorded" || !r.Assumed || r.Config != f.Config {
		t.Errorf("unrecorded: %+v", r)
	}
	p, _ := f.Config.Payload()
	RecordPushed(dir, Pushed{NodeID: "30:ed:a0:00:00:01", File: "a.json", Seq: 5, Payload: p, Time: time.Now()})
	if r := NodeRuns(dir, "a.json", &f, status("node", 5, "a")); r.State != "file" || r.Assumed {
		t.Errorf("file: %+v", r)
	}
	if r := NodeRuns(dir, "b.json", nil, status("node", 5, "a")); r.State != "other" || !strings.Contains(r.Text, "a.json") {
		t.Errorf("other: %+v", r)
	}
	g, _ := Save(dir, "a.json", []byte(`{"name":"a","forwarders":["1.1.1.1"]}`), f.Hash)
	if r := NodeRuns(dir, "a.json", &g, status("node", 5, "a")); r.State != "older" || r.Config == nil || r.Config.Name != "a" {
		t.Errorf("older: %+v", r)
	}
	// What the change does from there: the forwarders, live.
	r := NodeRuns(dir, "a.json", &g, status("node", 5, "a"))
	if ch := nodecfg.Compare(r.Config, g.Config, nil); !slices.Equal(ch.Live, []string{"forwarders"}) || ch.NeedsReboot() {
		t.Errorf("change %+v", ch)
	}
	if r := NodeRuns(dir, "a.json", &g, status("node", 6, "a")); r.State != "unrecorded" {
		t.Errorf("a later seq: %+v", r)
	}
	// Which node a config is: its name, or, when a name is missing, its address.
	c, _ := nodecfg.Parse([]byte(`{"name":"dns3","network":{"address":"192.0.2.252/23","gateway":"192.0.2.1"}}`))
	for _, tc := range []struct {
		host string
		st   release.NodeStatus
		want bool
	}{
		{"192.0.2.252", release.NodeStatus{}, true},
		{"203.0.113.1", status("node", 1, "dns3"), true},
		{"203.0.113.1", release.NodeStatus{Config: &release.ConfigStatus{IP: "192.0.2.252/23"}}, true}, // no name: its IP, from /status
		{"203.0.113.1", release.NodeStatus{Config: &release.ConfigStatus{Name: "x", IP: "203.0.113.1/24"}}, false},
		// Another name on the config's address: not its node (a config for that address)
		{"192.0.2.252", release.NodeStatus{Config: &release.ConfigStatus{Name: "dns2", IP: "192.0.2.252/23"}}, false},
	} {
		if Matches(c, tc.host, tc.st) != tc.want {
			t.Errorf("%s %+v: want %v", tc.host, tc.st.Config, tc.want)
		}
	}
	if !AtAddress(c, "192.0.2.252", release.NodeStatus{Config: &release.ConfigStatus{Name: "dns2"}}) {
		t.Error("at its address")
	}
}

// The editor's check on a node: its memory plan, the rollout's refusals, live or reboot.
func TestCheckRun(t *testing.T) {
	dir := t.TempDir()
	saved, _ := Save(dir, "a.json", []byte(withPass), "")
	ck := Check{Name: "a.json", Text: []byte(withPass), Saved: &saved, Catalog: "../../../boards", Board: "ws-s3-eth", DataDir: dir}
	r := ck.Run()
	if !r.OK || r.Error != "" || len(r.Memory) != 1 || !r.Memory[0].Fits || r.Changed || r.Diff != nil {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "s3cret") {
		t.Fatalf("the password in the result: %s", b)
	}
	if !strings.Contains(r.Payload, Hidden) || len(r.CPU) != 1 || !r.CPU[0].DFS || r.CPU[0].From != "image" {
		t.Errorf("%+v", r)
	}
	// A config the node refuses: the error as espdns config -check says it.
	ck.Text = []byte(`{"forwarders":["dns.google"]}`)
	if r := ck.Run(); r.OK || r.Error != "a.json: forwarders: not an IPv4 address: \"dns.google\"" {
		t.Errorf("%+v", r)
	}
	// On a node whose plan doesn't fit, and on firmware without services: refused.
	small := memplan.Values(memplan.Keys{}, "esp32s3-octal", 8192)
	small.BlocklistKB = 4096
	st := status("node", 3, "w")
	st.Memory = &release.MemoryStatus{Board: small}
	st.Board = "ws-s3-eth"
	st.Config.AddressFrom = "board"
	ck.Text, ck.Board, ck.Host, ck.Status = []byte(withPass), "", "192.0.2.252", &st
	r = ck.Run()
	if r.OK || r.Node == nil || !strings.Contains(r.Node.Refusal, "don't fit") || len(r.Memory) != 1 || r.Memory[0].Fits ||
		!strings.Contains(r.Memory[0].Error, "PSRAM") {
		t.Fatalf("%+v %+v", r, r.Node)
	}
	// "no network" for a node on its config's address; a move; zones: a reboot.
	st.Memory, st.Config.AddressFrom = nil, "config"
	if r := ck.Run(); r.OK || !strings.Contains(r.Node.Refusal, "has no network") {
		t.Errorf("no network: %+v", r.Node)
	}
	ck.Text = []byte(`{"name":"w","network":{"address":"192.0.2.9/23","gateway":"192.0.2.1"},"secondary":{"zones":["x.example"]}}`)
	r = ck.Run()
	// (compared with the file as saved, which has a Wi-Fi network this one drops)
	if !r.OK || r.Node.Moves != "192.0.2.9" || !slices.Equal(r.Node.Change.Reboot, []string{nodecfg.ReasonAddress, nodecfg.ReasonWifi}) ||
		!slices.Equal(r.Node.Change.Maybe, []string{nodecfg.ReasonZones}) || !r.Node.Running.Assumed {
		t.Errorf("move: %+v %+v", r, r.Node)
	}
	if len(r.Diff) == 0 || !r.Changed {
		t.Errorf("diff %v", r.Diff)
	}
	for _, l := range r.Diff {
		if strings.Contains(l.Text, "s3cret") {
			t.Errorf("the password in the diff: %s", l.Text)
		}
	}
	ck.Text = []byte(`{"name":"w","network":{"address":"192.0.2.252/23","gateway":"192.0.2.1"},"hosted":{"enabled":false}}`)
	if r := ck.Run(); r.OK || !strings.Contains(r.Node.Refusal, "turns services on or off") {
		t.Errorf("old firmware: %+v", r.Node)
	}
}

// makeData is `make -s data` in controller/ with args, as a top-level make: the test's own
// environment without what an outer make passes its sub-makes. Run by `make -C controller
// test`, the go test would hand them on: MAKELEVEL (a sub-make prints its directory) and
// MAKEFLAGS, which GNU make 4.3 gives -w when -C is used (4.4 doesn't), an explicit -w that
// -s doesn't turn off: "make[1]: Entering directory ..." in output these tests read.
// --no-print-directory as well, whatever else asks for it.
func makeData(args ...string) *exec.Cmd {
	cmd := exec.Command("make", append([]string{"-s", "--no-print-directory", "-C", "../..", "data"}, args...)...)
	for _, kv := range os.Environ() {
		switch k, _, _ := strings.Cut(kv, "="); k {
		case "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "MAKE_TERMOUT", "MAKE_TERMERR":
		default:
			cmd.Env = append(cmd.Env, kv)
		}
	}
	return cmd
}

// make data on a new data directory, as any fresh install runs it: the directories, and
// nothing in them: no settings.json, no node configs, no zones. The repo's examples
// (configs/example-*.json) are never copied as live settings or configs.
func TestMakeDataFresh(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	data := filepath.Join(t.TempDir(), "data")
	cmd := makeData("DATA="+data, "LOCAL_MK=/dev/null")
	cmd.Env = append(cmd.Env, "SETTINGS_SEED=", "CONFIG_SEEDS=")
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) != 0 {
		t.Fatalf("make data: %v\n%s", err, out)
	}
	var found []string
	filepath.WalkDir(data, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) != 0 {
		t.Fatalf("a fresh data directory holds %v", found)
	}
	for _, d := range []string{data, Path(data), filepath.Join(data, "zones")} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Fatalf("%s: %v", d, err)
		}
	}
}

// make data with a deployment's seeds (SETTINGS_SEED, CONFIG_SEEDS: its own files, outside
// the repo): each seed copied once (0600), never over a file that is there, a difference
// noted; fleet.json is the settings' old seed and example-*.json an example, not configs.
func TestMakeDataSeeds(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make")
	}
	seeds, data := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(seeds, "dns2.json"), []byte(`{"name":"dns2"}`), 0o644)
	os.WriteFile(filepath.Join(seeds, "dns3.json"), []byte(`{"name":"dns3"}`), 0o644)
	os.WriteFile(filepath.Join(seeds, "fleet.json"), []byte(`{"nodes":[]}`), 0o644)
	os.WriteFile(filepath.Join(seeds, "example-node.json"), []byte(`{"name":"node1"}`), 0o644)
	os.MkdirAll(Path(data), 0o755)
	os.WriteFile(filepath.Join(Path(data), "dns3.json"), []byte(`{"name":"mine"}`), 0o600)
	run := func() string {
		cmd := makeData("DATA="+data, "CONFIG_SEEDS="+seeds, "SETTINGS_SEED="+filepath.Join(seeds, "fleet.json"),
			"LOCAL_MK=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make data: %v\n%s", err, out)
		}
		return string(out)
	}
	out := run()
	if !strings.Contains(out, "copied "+filepath.Join(seeds, "dns2.json")) || !strings.Contains(out, "dns3.json differs") ||
		strings.Contains(out, "configs/fleet.json") {
		t.Errorf("first run:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(Path(data), "dns3.json")); string(b) != `{"name":"mine"}` {
		t.Errorf("dns3.json overwritten: %s", b)
	}
	if mode(t, filepath.Join(Path(data), "dns2.json")) != 0o600 {
		t.Errorf("dns2.json mode %v", mode(t, filepath.Join(Path(data), "dns2.json")))
	}
	for _, n := range []string{"fleet.json", "example-node.json"} {
		if _, err := os.Stat(filepath.Join(Path(data), n)); err == nil {
			t.Error(n, "copied as a config")
		}
	}
	if b, _ := os.ReadFile(filepath.Join(data, "settings.json")); string(b) != `{"nodes":[]}` {
		t.Errorf("settings.json not seeded: %s", b)
	}
	os.WriteFile(filepath.Join(Path(data), "dns2.json"), []byte(`{"name":"edited"}`), 0o600)
	out = run()
	if strings.Contains(out, "copied") || !strings.Contains(out, "dns2.json differs") {
		t.Errorf("second run:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(Path(data), "dns2.json")); string(b) != `{"name":"edited"}` {
		t.Errorf("dns2.json overwritten: %s", b)
	}
}

// The password as nodecfg.Parse reads it is masked however its keys are spelled: encoding/json
// matches keys case-insensitively, so a hand-edited "WiFi": {"Password": ...} is the
// password the node gets.
func TestMaskKeysAsParsed(t *testing.T) {
	for _, text := range []string{
		`{"WiFi":{"ssid":"x","Password":"hunter22"}}`,
		`{"WIFI":{"ssid":"x","PASSWORD":"hunter22"}}`,
		`{"wifi":{"ssid":"x","paſsword":"hunter22"}}`, // ſ folds to s, as encoding/json folds it
		`{"wifi":{"ssid":"x","password":"hunter22"}}`,
	} {
		c, err := nodecfg.Parse([]byte(text))
		if err != nil || c.Wifi == nil || c.Wifi.Password == nil || *c.Wifi.Password != "hunter22" {
			t.Fatalf("%s: not the password as parsed: %v", text, err)
		}
		m, ok := Mask([]byte(text))
		if !ok || strings.Contains(string(m), "hunter22") {
			t.Errorf("%s: masked as %s", text, m)
		}
		if back, err := Unmask(m, []byte(text)); err != nil || string(back) != text {
			t.Errorf("%s: unmasked as %s (%v)", text, back, err)
		}
	}
	// More after the object (a hand-edited file): masked anyway.
	if m, _ := Mask([]byte(`{"name":"a"} {"wifi":{"ssid":"x","password":"hunter22"}}`)); strings.Contains(string(m), "hunter22") {
		t.Errorf("trailing object: %s", m)
	}
	// A key given twice: the one nodecfg.Parse takes (the last) is the one put back.
	saved := `{"wifi":{"ssid":"x","password":"firstpass","password":"lastpass1"}}`
	c, _ := nodecfg.Parse([]byte(saved))
	m, _ := Mask([]byte(saved))
	back, err := Unmask([]byte(`{"wifi":{"ssid":"x","password":"`+Hidden+`"}}`), []byte(saved))
	if err != nil || !strings.Contains(string(back), `"`+*c.Wifi.Password+`"`) || strings.Contains(string(m), "pass1") {
		t.Errorf("duplicate key: parsed %q, put back %s (%v), masked %s", *c.Wifi.Password, back, err, m)
	}
}
