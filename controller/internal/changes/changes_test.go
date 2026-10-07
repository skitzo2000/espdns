package changes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

const zoneA = `$ORIGIN example.com.
$TTL 300
@ IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 300
@ IN NS ns.example.com.
ns IN A 192.0.2.1
`

func zoneWith(serial, addr string) []byte {
	return []byte(strings.Replace(strings.Replace(zoneA, " 1 3600", " "+serial+" 3600", 1), "192.0.2.1", addr, 1))
}

func newStore(t *testing.T) (*Store, string) {
	dir := t.TempDir()
	return New(dir), dir
}

func mustAdd(t *testing.T, s *Store, e Edit) Change {
	t.Helper()
	c, err := s.Add(e)
	if err != nil {
		t.Fatalf("add %+v: %v", e, err)
	}
	return c
}

// A change waits: the file is untouched, the view is what the change makes it, and the
// next edit of the file stacks on it.
func TestAddStacksOnPending(t *testing.T) {
	s, dir := newStore(t)
	if err := zonefiles.Store(dir).Save("example.com.zone", zoneWith("1", "192.0.2.1"), ""); err != nil {
		t.Fatal(err)
	}
	cur, _ := Current(dir, Zone, "example.com.zone")
	a := mustAdd(t, s, Edit{Kind: Zone, Name: "example.com.zone", Text: zoneWith("2", "192.0.2.2"), Hash: cur.Hash, Who: "admin"})
	if a.Base != cur.Hash || a.Hash != filestore.Hash(zoneWith("2", "192.0.2.2")) || a.Summary != "Change zone example.com" || a.Who != "admin" {
		t.Errorf("change %+v", a)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "zones", "example.com.zone")); string(b) != string(zoneWith("1", "192.0.2.1")) {
		t.Error("the file changed before an apply")
	}
	v, err := s.Effective(Zone, "example.com.zone")
	if err != nil || v.Hash != a.Hash || !slices.Equal(v.Pending, []string{a.ID}) || string(v.Text) != string(zoneWith("2", "192.0.2.2")) {
		t.Fatalf("view %+v %v", v, err)
	}
	// On the file's version: refused, the pending change is the version now.
	if _, err := s.Add(Edit{Kind: Zone, Name: "example.com.zone", Text: zoneWith("3", "192.0.2.3"), Hash: cur.Hash}); !errors.Is(err, ErrChanged) {
		t.Errorf("an edit of the version before: %v", err)
	}
	b := mustAdd(t, s, Edit{Kind: Zone, Name: "example.com.zone", Text: zoneWith("3", "192.0.2.3"), Hash: a.Hash, Summary: "  Move ns  "})
	if b.Base != a.Hash || b.Summary != "Move ns" {
		t.Errorf("stacked %+v", b)
	}
	// The same text again: nothing to change.
	if _, err := s.Add(Edit{Kind: Zone, Name: "example.com.zone", Text: zoneWith("3", "192.0.2.3"), Hash: b.Hash}); !errors.Is(err, ErrNoChange) {
		t.Errorf("no change: %v", err)
	}
	// Kept across a restart of the controller.
	cs, err := New(dir).List()
	if err != nil || len(cs) != 2 || cs[0].ID != a.ID || cs[1].ID != b.ID {
		t.Errorf("reloaded %+v %v", cs, err)
	}
	if cs := Chains(cs); len(cs) != 1 || len(cs[0]) != 2 {
		t.Errorf("chains %+v", cs)
	}
}

// Every change is checked as its store checks a save, before it waits.
func TestAddRefusals(t *testing.T) {
	s, dir := newStore(t)
	cases := []struct {
		e    Edit
		want string
	}{
		{Edit{Kind: "nope", Name: "x"}, "config, zone, source, lists or firmware"},
		{Edit{Kind: Zone, Name: "../x.zone", Text: []byte(zoneA)}, "zone"},
		{Edit{Kind: Zone, Name: "example.com.zone", Text: []byte("not a zone")}, ""},
		{Edit{Kind: Config, Name: "dns2.json", Text: []byte(`{"name": "dns2", "nope": 1}`)}, "nope"},
		{Edit{Kind: Lists, Name: "other.json", Text: []byte(`{"lists": []}`)}, "lists.json"},
		{Edit{Kind: Lists, Name: "lists.json", Text: []byte(`{"lists": [{"name": "Bad Name"}]}`)}, ""},
		{Edit{Kind: Source, Name: "overrides.txt", Delete: true}, "no such file"},
		{Edit{Kind: Source, Name: "overrides.txt", Delete: true, Text: []byte("x")}, "no text"},
		{Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Hash: "abc"}, "changed"},
		{Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Nodes: []string{"x"}}, "no firmware or nodes"},
		{Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Summary: "two\nlines"}, "one line"},
		{Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Summary: strings.Repeat("x", MaxSummary+1)}, "at most"},
		{Edit{Kind: Firmware, Firmware: "builds/p4"}, "names the firmware and the nodes"},
		{Edit{Kind: Firmware, Firmware: "builds/p4", Nodes: []string{"a", "a"}}, "twice"},
		{Edit{Kind: Firmware, Name: "x", Firmware: "builds/p4", Nodes: []string{"a"}}, "only"},
	}
	for _, c := range cases {
		if _, err := s.Add(c.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.e, err)
		}
	}
	// One firmware update per node.
	mustAdd(t, s, Edit{Kind: Firmware, Firmware: "builds/p4", Nodes: []string{"192.0.2.2"}})
	if _, err := s.Add(Edit{Kind: Firmware, Firmware: "images/x", Nodes: []string{"192.0.2.3", "192.0.2.2"}}); err == nil ||
		!strings.Contains(err.Error(), "already has a firmware update pending") {
		t.Errorf("two updates for a node: %v", err)
	}
	if cs, _ := s.List(); len(cs) != 1 {
		t.Errorf("refused changes kept: %+v", cs)
	}
	if _, err := os.Stat(filepath.Join(dir, "zones")); err == nil {
		t.Error("a refused change wrote a file")
	}
}

func TestLimits(t *testing.T) {
	s, _ := newStore(t)
	for i := range MaxChanges {
		mustAdd(t, s, Edit{Kind: Firmware, Firmware: "builds/p4", Nodes: []string{string(rune('a'+i%26)) + strings.Repeat("x", i/26)}})
	}
	if _, err := s.Add(Edit{Kind: Firmware, Firmware: "builds/p4", Nodes: []string{"last"}}); !errors.Is(err, ErrFull) {
		t.Errorf("one too many: %v", err)
	}
}

// Discarding a change discards those stacked on it; an apply's held changes can't be.
func TestDiscard(t *testing.T) {
	s, _ := newStore(t)
	a := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n")})
	f := mustAdd(t, s, Edit{Kind: Firmware, Firmware: "builds/p4", Nodes: []string{"192.0.2.2"}})
	b := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\nb.example\n"), Hash: a.Hash})
	if a.Summary != "Add blocking source overrides.txt" {
		t.Errorf("summary %q", a.Summary)
	}
	if err := s.Hold([]string{b.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Discard(a.ID); !errors.Is(err, ErrHeld) {
		t.Errorf("a change stacked under a held one: %v", err)
	}
	if _, err := s.DiscardAll(); !errors.Is(err, ErrHeld) {
		t.Errorf("all, one held: %v", err)
	}
	s.Release([]string{b.ID})
	d, err := s.Discard(a.ID)
	if err != nil || !slices.Equal(d.IDs, []string{a.ID, b.ID}) || len(d.PutBack) != 0 {
		t.Fatalf("discard %+v %v", d, err)
	}
	if cs, _ := s.List(); len(cs) != 1 || cs[0].ID != f.ID {
		t.Errorf("left %+v", cs)
	}
	if _, err := os.Stat(s.path(a.ID, ".txt")); err == nil {
		t.Error("a discarded change's text is kept")
	}
	if _, err := s.Discard(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("again: %v", err)
	}
	if err := s.Hold([]string{a.ID}); !errors.Is(err, ErrNotFound) {
		t.Errorf("hold a discarded change: %v", err)
	}
	d, err = s.DiscardAll()
	if err != nil || !slices.Equal(d.IDs, []string{f.ID}) {
		t.Errorf("all %+v %v", d, err)
	}
	if cs, _ := s.List(); len(cs) != 0 {
		t.Errorf("left %+v", cs)
	}
}

// An apply that stopped after writing: a discard puts the file back as it was, and leaves
// a change that sends it to the nodes again.
func TestDiscardWritten(t *testing.T) {
	s, dir := newStore(t)
	src := blocking.Sources(dir)
	if err := src.Save("overrides.txt", []byte("old.example\n"), ""); err != nil {
		t.Fatal(err)
	}
	old, _ := Current(dir, Source, "overrides.txt")
	a := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Hash: old.Hash, Summary: "Always block a.example"})
	b := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\nb.example\n"), Hash: a.Hash})
	n := mustAdd(t, s, Edit{Kind: Zone, Name: "example.com.zone", Text: zoneWith("1", "192.0.2.1")})
	// The apply writes them.
	if err := src.Save("overrides.txt", []byte("a.example\nb.example\n"), old.Hash); err != nil {
		t.Fatal(err)
	}
	if err := zonefiles.Store(dir).Save("example.com.zone", zoneWith("1", "192.0.2.1"), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkWritten([]string{a.ID, b.ID, n.ID}, map[string][]byte{a.ID: []byte("old.example\n"), n.ID: nil}); err != nil {
		t.Fatal(err)
	}
	// The second: the file back to the first's text; the first still pending.
	d, err := s.Discard(b.ID)
	if err != nil || !slices.Equal(d.IDs, []string{b.ID}) || len(d.PutBack) != 0 {
		t.Fatalf("discard %+v %v", d, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "blocking/sources/overrides.txt")); string(got) != "a.example\n" {
		t.Errorf("file %q", got)
	}
	// The first: the file back as it was, and a put-back.
	d, err = s.Discard(a.ID)
	if err != nil || !slices.Equal(d.IDs, []string{a.ID}) || len(d.PutBack) != 1 {
		t.Fatalf("discard %+v %v", d, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "blocking/sources/overrides.txt")); string(got) != "old.example\n" {
		t.Errorf("file %q", got)
	}
	p := d.PutBack[0]
	if !p.PutBack || p.Base != old.Hash || p.Hash != old.Hash || p.Summary != "Put back on the nodes: Always block a.example" {
		t.Errorf("put back %+v", p)
	}
	if v, _ := s.Effective(Source, "overrides.txt"); v.Hash != old.Hash || !slices.Equal(v.Pending, []string{p.ID}) {
		t.Errorf("view %+v", v)
	}
	// A new zone written, discarded: the file deleted, a put-back that deletes it.
	d, err = s.Discard(n.ID)
	if err != nil || len(d.PutBack) != 1 || !d.PutBack[0].Delete {
		t.Fatalf("discard the new zone %+v %v", d, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "zones/example.com.zone")); !os.IsNotExist(err) {
		t.Errorf("the new zone is still there: %v", err)
	}
	// Discarding every change keeps the put-backs (the nodes may hold what was written),
	// and discards a change stacked on one.
	c := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("c.example\n"), Hash: old.Hash})
	if d, err := s.DiscardAll(); err != nil || !slices.Equal(d.IDs, []string{c.ID}) || len(d.PutBack) != 0 {
		t.Errorf("all %+v %v", d, err)
	}
	if cs, _ := s.List(); len(cs) != 2 || !cs[0].PutBack || !cs[1].PutBack {
		t.Errorf("left %+v", cs)
	}
	// A put-back by itself is discarded plainly.
	if d, err := s.Discard(p.ID); err != nil || !slices.Equal(d.IDs, []string{p.ID}) || len(d.PutBack) != 0 {
		t.Errorf("the put-back %+v %v", d, err)
	}
}

func TestAppliedAndHold(t *testing.T) {
	s, _ := newStore(t)
	a := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n")})
	b := mustAdd(t, s, Edit{Kind: Source, Name: "overrides-allow.txt", Text: []byte("b.example\n")})
	if err := s.Hold([]string{a.ID}); err != nil || !s.Held(a.ID) || s.Held(b.ID) {
		t.Fatalf("hold: %v", err)
	}
	if err := s.Applied([]string{a.ID}); err != nil {
		t.Fatal(err)
	}
	s.Release([]string{a.ID})
	if cs, _ := s.List(); len(cs) != 1 || cs[0].ID != b.ID {
		t.Errorf("left %+v", cs)
	}
	if _, err := os.Stat(s.path(a.ID, ".txt")); err == nil {
		t.Error("an applied change's text is kept")
	}
	// A text file that isn't the change's is refused.
	os.WriteFile(s.path(b.ID, ".txt"), []byte("other\n"), 0o600)
	if _, err := s.Text(b); err == nil {
		t.Error("a changed text read")
	}
}

// A change marked written whose save then failed: unmarked, a discard leaves the file (saved
// by someone else meanwhile) as it is.
func TestUnwritten(t *testing.T) {
	s, dir := newStore(t)
	src := blocking.Sources(dir)
	if err := src.Save("overrides.txt", []byte("old.example\n"), ""); err != nil {
		t.Fatal(err)
	}
	old, _ := Current(dir, Source, "overrides.txt")
	a := mustAdd(t, s, Edit{Kind: Source, Name: "overrides.txt", Text: []byte("a.example\n"), Hash: old.Hash})
	if err := s.MarkWritten([]string{a.ID}, map[string][]byte{a.ID: []byte("old.example\n")}); err != nil {
		t.Fatal(err)
	}
	if err := src.Save("overrides.txt", []byte("other.example\n"), old.Hash); err != nil {
		t.Fatal(err)
	}
	if err := s.Unwritten([]string{a.ID}); err != nil {
		t.Fatal(err)
	}
	if cs, _ := s.List(); len(cs) != 1 || cs[0].Written || s.Base(a.ID) != nil {
		t.Fatalf("still written %+v", cs)
	}
	if d, err := s.Discard(a.ID); err != nil || len(d.PutBack) != 0 {
		t.Fatalf("discard %+v %v", d, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "blocking/sources/overrides.txt")); string(got) != "other.example\n" {
		t.Errorf("file %q", got)
	}
}

// AddAll adds every change or none: each checked on the pending changes and the ones
// before it, nothing left behind by a refused one.
func TestAddAll(t *testing.T) {
	s, dir := newStore(t)
	cur, _ := Current(dir, Zone, "example.com.zone")
	cs, err := s.AddAll([]Edit{
		{Kind: Zone, Name: "example.com.zone", Text: zoneWith("1", "192.0.2.1"), Hash: cur.Hash},
		{Kind: Firmware, Firmware: "images/esp32s3", Nodes: []string{"192.0.2.53"}},
	})
	if err != nil || len(cs) != 2 {
		t.Fatalf("added %+v %v", cs, err)
	}
	// Stacked on the one before it in the same call.
	added, err := s.AddAll([]Edit{
		{Kind: Zone, Name: "example.com.zone", Text: zoneWith("2", "192.0.2.2"), Hash: cs[0].Hash},
		{Kind: Zone, Name: "example.com.zone", Text: zoneWith("3", "192.0.2.3"), Hash: filestore.Hash(zoneWith("2", "192.0.2.2"))},
	})
	if err != nil || len(added) != 2 || added[1].Base != added[0].Hash {
		t.Fatalf("stacked %+v %v", added, err)
	}
	// A refused one (its node has a pending update, from this call): none added, no text left.
	before, _ := os.ReadDir(filepath.Join(dir, Dir))
	if _, err := s.AddAll([]Edit{
		{Kind: Zone, Name: "example.com.zone", Text: zoneWith("4", "192.0.2.4"), Hash: added[1].Hash},
		{Kind: Firmware, Firmware: "images/esp32s3", Nodes: []string{"192.0.2.54"}},
		{Kind: Firmware, Firmware: "builds/p4-board", Nodes: []string{"192.0.2.54"}},
	}); err == nil || !strings.Contains(err.Error(), "already has a firmware update pending") {
		t.Errorf("refused: %v", err)
	}
	if l, _ := s.List(); len(l) != 4 {
		t.Errorf("pending %d", len(l))
	}
	if after, _ := os.ReadDir(filepath.Join(dir, Dir)); len(after) != len(before) {
		t.Errorf("files %d, were %d", len(after), len(before))
	}
	// Full part way: none.
	var es []Edit
	for i := 0; i < MaxChanges; i++ {
		es = append(es, Edit{Kind: Firmware, Firmware: "images/esp32s3", Nodes: []string{fmt.Sprintf("n%d", i)}})
	}
	if _, err := s.AddAll(es); !errors.Is(err, ErrFull) {
		t.Errorf("full: %v", err)
	}
	if l, _ := s.List(); len(l) != 4 {
		t.Errorf("pending after full %d", len(l))
	}
}
