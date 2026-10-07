package updates

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func status(image, board, version, elf, built, name string) *release.NodeStatus {
	st := &release.NodeStatus{Image: image, Board: board, Version: version, ElfSHA256: elf, Built: built}
	if name != "" {
		st.Config = &release.ConfigStatus{Name: name}
	}
	return st
}

func TestVersion(t *testing.T) {
	old := Of("0.0.3", "Oct  7 2026 12:00:00", "00000000000000a1")
	newer := Of("0.0.10", "Oct  3 2026 09:30:00", "00000000000000b2")
	// By version, whatever the build times say.
	if c, ok := Compare(newer, old); !ok || c <= 0 {
		t.Errorf("newer vs old: %d %v", c, ok)
	}
	if c, ok := Compare(old, newer); !ok || c >= 0 {
		t.Errorf("old vs newer: %d %v", c, ok)
	}
	if c, ok := Compare(Of("0.1.0", "", "00000000000000c1"), Of("0.0.99", "", "00000000000000c2")); !ok || c <= 0 {
		t.Errorf("minor over patch: %d %v", c, ok)
	}
	// The same build, whatever its text and time say.
	if c, ok := Compare(old, Of("other", "", "00000000000000A1")); !ok || c != 0 {
		t.Errorf("same build: %d %v", c, ok)
	}
	// One version, two builds: the build time breaks the tie.
	rebuilt := Of("0.0.3", "Oct  8 2026 08:00:00", "00000000000000c3")
	if c, ok := Compare(rebuilt, old); !ok || c <= 0 {
		t.Errorf("rebuilt vs old: %d %v", c, ok)
	}
	if c, ok := Compare(old, rebuilt); !ok || c >= 0 {
		t.Errorf("old vs rebuilt: %d %v", c, ok)
	}
	// ... and without one to break it, or the same second: not ordered.
	untimed := Of("0.0.3", "garbage", "00000000000000c4")
	if _, ok := Compare(old, untimed); ok {
		t.Error("one version, no build time: ordered")
	}
	if _, ok := Compare(old, Of("0.0.3", "Oct  7 2026 12:00:00", "00000000000000c5")); ok {
		t.Error("one version, same second: ordered")
	}
	// A build without a version (a commit, as firmware from before versions says) is not
	// ordered against any other, whatever the build times.
	commit := Of("3fbae0a", "Oct  1 2026 08:00:00", "00000000000000c6")
	if _, ok := Compare(old, commit); ok {
		t.Error("a commit vs a version: ordered")
	}
	if _, ok := Compare(commit, Of("bff81c1-dirty", "Oct  9 2026 08:00:00", "00000000000000c7")); ok {
		t.Error("two commits: ordered")
	}
	// The newer pick of two builds: by Compare, else the one with a version, else (one
	// version) the one with a build time.
	if !Later(newer, old) || Later(old, newer) || !Later(rebuilt, old) {
		t.Error("later: ordered")
	}
	if !Later(old, commit) || Later(commit, old) || Later(commit, commit) {
		t.Error("later: a version over none")
	}
	if !Later(old, untimed) || Later(untimed, old) || Later(untimed, untimed) {
		t.Error("later: a build time over none")
	}
	if Later(Of("0.0.2", "", "00000000000000c8"), untimed) {
		t.Error("later: an older version for its build time")
	}
	// What is shown: the descriptor's version, plain, else the build.
	if v := Of(" 0.0.4\x00\n", "", "00000000000000d4"); v.Text != "0.0.4" || !v.ok {
		t.Errorf("text %q", v.Text)
	}
	if v := Of("", "", "00000000000000d4"); v.Text != "00000000000000d4" || v.ok {
		t.Errorf("no version: %q", v.Text)
	}
	if v := Of(strings.Repeat("v", 40), "", "00000000000000d4"); len(v.Text) != maxText {
		t.Errorf("long: %q", v.Text)
	}
}

// fleet is a data directory with a P4 board's build, an exported S3 image and a board
// whose definition is missing.
func fleet(t *testing.T) (dir, catalog string) {
	dir, catalog = t.TempDir(), t.TempDir()
	write(t, filepath.Join(catalog, "p4-board.json"), []byte(`{"image": "esp32p4-rev1"}`))
	write(t, filepath.Join(dir, "firmware/builds/p4-board/dns2.bin"), fakenode.AppBuilt("0.0.4", "00000000000000b2", "Oct  7 2026", "09:30:00"))
	write(t, filepath.Join(dir, "firmware/builds/gone/dns2.bin"), fakenode.App("x", "00000000000000ff"))
	write(t, filepath.Join(dir, "firmware/images/esp32s3/image.json"), []byte(`{"image": "esp32s3", "chip": "esp32s3"}`))
	write(t, filepath.Join(dir, "firmware/images/esp32s3/app.bin"), fakenode.AppBuilt("0.0.3", "00000000000000c1", "Oct  5 2026", "08:00:00"))
	return dir, catalog
}

func TestReport(t *testing.T) {
	dir, catalog := fleet(t)
	builds := Builds(dir, catalog)
	if len(builds) != 3 {
		t.Fatalf("builds %+v", builds)
	}
	if b := builds[1]; b.Source != "builds/p4-board" || b.Image != "esp32p4-rev1" || b.Text != "0.0.4" || b.Build != "00000000000000b2" || b.Error != "" {
		t.Errorf("the P4's build: %+v", b)
	}
	if b := builds[0]; b.Source != "builds/gone" || b.Error == "" {
		t.Errorf("a board without a definition: %+v", b)
	}
	ns := []Node{
		{Host: "192.0.2.52", Listed: true, Online: true, Status: status("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "dns2")},
		{Host: "192.0.2.53", Listed: true, Online: true, Status: status("esp32s3", "s3-board", "0.0.3", "00000000000000c1", "Oct  5 2026 08:00:00", "dns3")},
		{Host: "192.0.2.54", Listed: true, Status: status("esp32s3", "s3-board", "0.0.9", "00000000000000d1", "Oct  1 2026 08:00:00", "")},
		{Host: "192.0.2.55", Listed: true, Status: status("esp32c6", "", "1", "00000000000000e1", "Oct  1 2026 08:00:00", "")},
		{Host: "192.0.2.56", Listed: true},
		{Host: "192.0.2.57", Listed: true, Status: status("esp32s3", "", "f00d", "00000000000000d1", "Oct  1 2026 08:00:00", "")},
		{Host: "192.0.2.58", Listed: false, Status: status("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "")},
		{Host: "192.0.2.59", Listed: true, Status: status("esp32p4-rev1", "other-p4", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "")},
		{Host: "192.0.2.60", Listed: true, Status: status("esp32p4-rev1", "", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "")},
		// The newest build's version, built before it and after it: the build time decides.
		{Host: "192.0.2.61", Listed: true, Status: status("esp32p4-rev1", "p4-board", "0.0.4", "00000000000000a4", "Oct  6 2026 12:00:00", "")},
		{Host: "192.0.2.62", Listed: true, Status: status("esp32p4-rev1", "p4-board", "0.0.4", "00000000000000a5", "Oct  8 2026 12:00:00", "")},
		// A build from before versions (its descriptor says a commit): not ordered.
		{Host: "192.0.2.63", Listed: true, Status: status("esp32p4-rev1", "p4-board", "3fbae0a", "00000000000000a6", "Oct  3 2026 12:00:00", "")},
	}
	pending := []changes.Change{{ID: "c1", Kind: changes.Firmware, Firmware: "builds/p4-board", Nodes: []string{"192.0.2.60"}, Summary: "Update 192.0.2.60"}}
	r := For(ns, builds, pending)
	if r.Scheme != Scheme {
		t.Errorf("scheme %q", r.Scheme)
	}
	want := []string{Available, Current, Newer, NoBuild, Unknown, Unordered, Available, NoBuild, Available, Available, Newer, Unordered}
	for i, u := range r.Nodes {
		if u.State != want[i] {
			t.Errorf("%s: %s (%s), want %s", u.Host, u.State, u.Why, want[i])
		}
	}
	dns2 := r.Nodes[0]
	if dns2.Name != "dns2" || dns2.Runs.Text != "0.0.1" || dns2.Newest.Source != "builds/p4-board" || dns2.Why != "Update available: 0.0.1 → 0.0.4" {
		t.Errorf("dns2 %+v", dns2)
	}
	if w := r.Nodes[9].Why; w != "Update available: 0.0.4 → 0.0.4 (a later build of it)" {
		t.Errorf("a later build: %q", w)
	}
	if w := r.Nodes[10].Why; w != "It runs 0.0.4, built later than any build of it here" {
		t.Errorf("an earlier build: %q", w)
	}
	if r.Nodes[1].Newest.Source != "images/esp32s3" {
		t.Errorf("the S3 takes its image's export: %+v", r.Nodes[1])
	}
	if u := r.Nodes[8]; u.Pending != "c1" || u.Offered() {
		t.Errorf("pending: %+v", u)
	}
	// Offered: listed, available, none pending.
	if !slices.Equal(r.Available, []string{"192.0.2.52", "192.0.2.61"}) {
		t.Errorf("available %v", r.Available)
	}
}

func TestPlan(t *testing.T) {
	dir, catalog := fleet(t)
	builds := Builds(dir, catalog)
	ns := []Node{
		{Host: "192.0.2.52", Listed: true, Status: status("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "dns2")},
		{Host: "192.0.2.53", Listed: true, Status: status("esp32s3", "s3-board", "0.0.2", "00000000000000aa", "Oct  1 2026 08:00:00", "dns3")},
		{Host: "192.0.2.54", Listed: true, Status: status("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "")},
		{Host: "192.0.2.55", Listed: true, Status: status("esp32s3", "s3-board", "0.0.3", "00000000000000c1", "Oct  5 2026 08:00:00", "dns5")},
		{Host: "192.0.2.56", Listed: false, Status: status("esp32s3", "s3-board", "0.0.2", "00000000000000aa", "Oct  1 2026 08:00:00", "")},
	}
	r := For(ns, builds, nil)
	// Update all: one change per build, in the builds' order.
	offers, err := r.Plan(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 2 || offers[0].Source != "builds/p4-board" || !slices.Equal(offers[0].Nodes, []string{"192.0.2.52", "192.0.2.54"}) ||
		offers[1].Source != "images/esp32s3" || !slices.Equal(offers[1].Nodes, []string{"192.0.2.53"}) {
		t.Fatalf("offers %+v", offers)
	}
	if offers[0].Summary != "Update dns2, 192.0.2.54 from 0.0.1 to 0.0.4" || offers[0].To.Build != "00000000000000b2" {
		t.Errorf("summary %+v", offers[0])
	}
	// One node, the build the page showed.
	offers, err = r.Plan([]string{"192.0.2.53"}, map[string]string{"192.0.2.53": "00000000000000c1"})
	if err != nil || len(offers) != 1 || offers[0].Summary != "Update dns3 from 0.0.2 to 0.0.3" {
		t.Errorf("one: %+v %v", offers, err)
	}
	if _, err := r.Plan([]string{"192.0.2.53"}, map[string]string{"192.0.2.53": "00000000000000aa"}); !errors.Is(err, ErrMoved) {
		t.Errorf("another build since: %v", err)
	}
	for _, bad := range [][]string{{"192.0.2.55"}, {"192.0.2.56"}, {"192.0.2.99"}, {"192.0.2.52", "192.0.2.52"}, {""}} {
		if _, err := r.Plan(bad, nil); err == nil {
			t.Errorf("%v: planned", bad)
		}
	}
	// Nothing to update.
	if _, err := For(ns[3:4], builds, nil).Plan(nil, nil); err == nil {
		t.Error("nothing offered: planned")
	}
	// Many nodes: counted.
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, "a-long-node-name-"+strings.Repeat("x", 10))
	}
	if s := summary(many, []string{"1"}, "2"); s != "Update 20 nodes from 1 to 2" {
		t.Errorf("many: %q", s)
	}
	if s := summary([]string{"a"}, []string{"1", "2"}, "3"); s != "Update a to 3" {
		t.Errorf("from two: %q", s)
	}
}

// What a node or a build says is shown as one line of valid text, cut at a character.
func TestClean(t *testing.T) {
	if s := Clean(" dns2\n\x1b[31m ", 64); s != "dns2[31m" {
		t.Errorf("control: %q", s)
	}
	if s := Clean("a\xffb", 64); s != "ab" {
		t.Errorf("invalid UTF-8: %q", s)
	}
	if s := Clean(strings.Repeat("é", 20), 5); s != "éé" {
		t.Errorf("cut: %q", s)
	}
	if v := Of(strings.Repeat("é", 20), "", "00000000000000d4"); len(v.Text) > maxText || !utf8.ValidString(v.Text) {
		t.Errorf("version cut: %q", v.Text)
	}
}

// A node's config name with a control character (its /status says it) is shown, and an
// update of it summarized, without it: the summary a change takes is one plain line.
func TestPlanNameCleaned(t *testing.T) {
	dir, catalog := fleet(t)
	r := For([]Node{{Host: "192.0.2.52", Listed: true,
		Status: status("esp32p4-rev1", "p4-board", "0.0.1", "00000000000000a1", "Oct  3 2026 12:00:00", "dns2\nx"+strings.Repeat("y", 300))}},
		Builds(dir, catalog), nil)
	if n := r.Nodes[0].Name; strings.ContainsAny(n, "\n") || len(n) > maxName {
		t.Errorf("name %q", n)
	}
	offers, err := r.Plan(nil, nil)
	if err != nil || len(offers) != 1 {
		t.Fatalf("%+v %v", offers, err)
	}
	if err := changes.CheckSummary(offers[0].Summary); err != nil {
		t.Errorf("summary %q: %v", offers[0].Summary, err)
	}
}

// A build that can't be read says why without the data directory's path.
func TestBuildErrorNoPath(t *testing.T) {
	dir, catalog := fleet(t)
	write(t, filepath.Join(dir, "firmware/images/esp32s3/app.bin"), []byte("not an image"))
	for _, b := range Builds(dir, catalog) {
		if strings.Contains(b.Error, dir) {
			t.Errorf("%s: %s", b.Source, b.Error)
		}
		if b.Source == "images/esp32s3" && !strings.Contains(b.Error, "firmware/images/esp32s3/app.bin") {
			t.Errorf("why: %q", b.Error)
		}
	}
}
