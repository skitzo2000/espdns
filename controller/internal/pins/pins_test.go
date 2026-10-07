package pins

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPinAndSeq(t *testing.T) {
	data := t.TempDir()
	l := Open(data)
	if _, err := l.Pinned("192.0.2.53"); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("empty record: %v", err)
	}
	if rs, err := l.List(); err != nil || len(rs) != 0 {
		t.Fatalf("empty list: %v %v", rs, err)
	}
	if _, err := l.Seq("30:ed:a0:00:00:01", "config"); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("seq of a node not pinned: %v", err)
	}
	if err := l.SetSeq("30:ed:a0:00:00:01", "config", 5); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("set seq of a node not pinned: %v", err)
	}

	// IDs are kept lowercase, however they are given.
	if r, err := l.Pin("30:ED:A0:00:00:01", "192.0.2.53"); err != nil || r != "" {
		t.Fatal(r, err)
	}
	if id, err := l.Pinned("192.0.2.53"); err != nil || id != "30:ed:a0:00:00:01" {
		t.Fatal(id, err)
	}
	if s, err := l.Seq("30:ed:a0:00:00:01", "config"); err != nil || s != 0 {
		t.Fatal(s, err)
	}
	if err := l.SetSeq("30:ed:a0:00:00:01", "config", 1_800_000_000_000); err != nil {
		t.Fatal(err)
	}
	// Never back, nor the same seq twice.
	for _, s := range []uint64{1_800_000_000_000, 5} {
		if err := l.SetSeq("30:ed:a0:00:00:01", "config", s); err == nil {
			t.Errorf("seq %d taken after 1800000000000", s)
		}
	}
	// Durable: another Ledger on the same directory (another process) reads it.
	if s, err := Open(data).Seq("30:ED:A0:00:00:01", "config"); err != nil || s != 1_800_000_000_000 {
		t.Fatal(s, err)
	}

	// Moving keeps the seqs; another node pinned to the address takes it from the first,
	// which keeps its seqs for when it is pinned again.
	if r, err := l.Pin("30:ed:a0:00:00:01", "192.0.2.60"); err != nil || r != "" {
		t.Fatal(r, err)
	}
	if _, err := l.Pinned("192.0.2.53"); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("old address: %v", err)
	}
	if r, err := l.Pin("30:ed:a0:00:00:02", "192.0.2.60"); err != nil || r != "30:ed:a0:00:00:01" {
		t.Fatal(r, err)
	}
	if id, _ := l.Pinned("192.0.2.60"); id != "30:ed:a0:00:00:02" {
		t.Fatal(id)
	}
	if s, _ := l.Seq("30:ed:a0:00:00:01", "config"); s != 1_800_000_000_000 {
		t.Fatal("seqs lost when unpinned:", s)
	}
	rs, err := l.List()
	if err != nil || len(rs) != 2 || rs[0].ID != "30:ed:a0:00:00:02" || rs[1].Addr != "" {
		t.Fatalf("%+v %v", rs, err)
	}

	for _, bad := range []string{"", "30:ed:a0:00:00", "../../etc/passwd", "zz:ed:a0:00:00:01"} {
		if _, err := l.Pin(bad, "192.0.2.70"); err == nil {
			t.Errorf("pinned %q", bad)
		}
	}
	if _, err := l.Pin("30:ed:a0:00:00:03", ""); err == nil {
		t.Error("pinned to no address")
	}
}

// A record that can't be read stops a lookup rather than being skipped: it could be the pin
// that says the address is another node's.
func TestUnreadableRecord(t *testing.T) {
	data := t.TempDir()
	l := Open(data)
	if _, err := l.Pin("30:ed:a0:00:00:01", "192.0.2.53"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, Dir, "30eda0000002.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Pinned("192.0.2.53"); err == nil || errors.Is(err, ErrNotPinned) {
		t.Fatalf("unreadable record: %v", err)
	}
	// A record whose name and contents disagree.
	os.WriteFile(filepath.Join(data, Dir, "30eda0000002.json"), []byte(`{"id":"30:ed:a0:00:00:01","addr":"192.0.2.9"}`), 0o600)
	if _, err := l.Pinned("192.0.2.9"); err == nil || !strings.Contains(err.Error(), "names node") {
		t.Fatalf("mismatched record: %v", err)
	}
	// Two records for one address (edited by hand).
	os.WriteFile(filepath.Join(data, Dir, "30eda0000002.json"), []byte(`{"id":"30:ed:a0:00:00:02","addr":"192.0.2.53"}`), 0o600)
	if _, err := l.Pinned("192.0.2.53"); err == nil || !strings.Contains(err.Error(), "both pinned") {
		t.Fatalf("two pins: %v", err)
	}
	// Temporary files are not records.
	os.Remove(filepath.Join(data, Dir, "30eda0000002.json"))
	os.WriteFile(filepath.Join(data, Dir, ".tmp-123"), []byte("{"), 0o600)
	if id, err := l.Pinned("192.0.2.53"); err != nil || id != "30:ed:a0:00:00:01" {
		t.Fatal(id, err)
	}
}

// Next reads, picks and records as one step: pushes at once to one node, in the same
// millisecond, each get a seq of their own and none is refused for another's.
func TestNextAtOnce(t *testing.T) {
	l := Open(t.TempDir())
	if _, err := l.Next("30:ed:a0:00:00:01", "config", func(uint64) (uint64, error) { return 1, nil }); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("not pinned: %v", err)
	}
	if _, err := l.Pin("30:ed:a0:00:00:01", "192.0.2.53"); err != nil {
		t.Fatal(err)
	}
	const now, n = 1_800_000_000_000, 32
	var wg sync.WaitGroup
	got := make([]uint64, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = l.Next("30:ed:a0:00:00:01", "config", func(last uint64) (uint64, error) {
				return max(now, last+1), nil
			})
		}()
	}
	wg.Wait()
	seen := map[uint64]bool{}
	for i := range n {
		if errs[i] != nil || got[i] < now || got[i] >= now+n || seen[got[i]] {
			t.Errorf("push %d: seq %d, %v", i, got[i], errs[i])
		}
		seen[got[i]] = true
	}
	if s, _ := l.Seq("30:ed:a0:00:00:01", "config"); s != now+n-1 {
		t.Errorf("recorded %d", s)
	}
	// A refusal records nothing; a seq not above the last is refused.
	if _, err := l.Next("30:ed:a0:00:00:01", "config", func(uint64) (uint64, error) { return 0, errors.New("no") }); err == nil {
		t.Error("refusal passed")
	}
	if _, err := l.Next("30:ed:a0:00:00:01", "config", func(last uint64) (uint64, error) { return last, nil }); err == nil {
		t.Error("the same seq twice")
	}
	if s, _ := l.Seq("30:ed:a0:00:00:01", "config"); s != now+n-1 {
		t.Errorf("recorded %d after refusals", s)
	}
}

// A node not adopted yet (identify, on the Adopt page) is in the record pinned nowhere, so
// its seqs are kept, and adoption pins it with them; one pinned to an address is refused.
func TestUnpinned(t *testing.T) {
	l := Open(t.TempDir())
	if _, err := l.Unpinned("not-an-id"); err == nil {
		t.Fatal("a bad ID taken")
	}
	id, err := l.Unpinned("30:ED:A0:00:00:01")
	if err != nil || id != "30:ed:a0:00:00:01" {
		t.Fatal(id, err)
	}
	if rs, err := l.List(); err != nil || len(rs) != 1 || rs[0].Addr != "" {
		t.Fatalf("in the record, pinned nowhere: %+v %v", rs, err)
	}
	if _, err := l.Next(id, "control", func(last uint64) (uint64, error) { return last + 7, nil }); err != nil {
		t.Fatal(err)
	}
	// Again: the same record, its seq kept.
	if _, err := l.Unpinned(id); err != nil {
		t.Fatal(err)
	}
	if s, err := l.Seq(id, "control"); err != nil || s != 7 {
		t.Fatal(s, err)
	}
	// Adopted: pinned, with its seq.
	if _, err := l.Pin(id, "192.0.2.53"); err != nil {
		t.Fatal(err)
	}
	if s, err := l.Seq(id, "control"); err != nil || s != 7 {
		t.Fatal(s, err)
	}
	if _, err := l.Unpinned(id); err == nil || !strings.Contains(err.Error(), "pinned to 192.0.2.53") {
		t.Fatalf("pinned elsewhere: %v", err)
	}
}
