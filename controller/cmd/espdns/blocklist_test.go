package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
)

// The flags become the library's Request: the same compile a page asks for.
func TestBlocklistRequest(t *testing.T) {
	req, asJSON, err := blocklistRequest([]string{"-list", "rpz:https://feeds.example/rpz.zone", "-list", "hosts:h.txt",
		"-allow", "domains:ok.txt", "-out", "l.bin", "-max-change", "35", "-accept-change", "-xor", "0", "-json"})
	if err != nil {
		t.Fatal(err)
	}
	want := []blocklist.Source{{Kind: blocklist.RPZ, Path: "https://feeds.example/rpz.zone"},
		{Kind: blocklist.Hosts, Path: "h.txt"}, {Kind: blocklist.Domains, Path: "ok.txt", Allow: true}}
	if len(req.Sources) != 3 || req.Sources[0] != want[0] || req.Sources[1] != want[1] || req.Sources[2] != want[2] {
		t.Errorf("sources %+v", req.Sources)
	}
	if req.Out != "l.bin" || req.MaxChange == nil || *req.MaxChange != 35 || !req.AcceptChange || req.XorBits != 0 || req.Bits != 44 ||
		req.MinChange != nil || !asJSON || !req.Sources[0].IsURL() {
		t.Errorf("request %+v", req)
	}
	// Unset is the default; 0 given is 0 (no floor; no change above it)
	if req, _, _ = blocklistRequest([]string{"-list", "domains:a", "-out", "o", "-min-change", "0"}); req.MinChange == nil ||
		*req.MinChange != 0 || req.MaxChange != nil {
		t.Errorf("-min-change 0: %+v", req)
	}
	if req, _, err = blocklistRequest([]string{"-list", "domains:a", "-out", "o", "-max-change", "0"}); err != nil ||
		req.MaxChange == nil || *req.MaxChange != 0 || req.MinChange != nil {
		t.Errorf("-max-change 0: %+v, %v", req, err)
	}
	for _, args := range [][]string{
		{"-list", "domains:a"},           // no -out
		{"-out", "o"},                    // no list
		{"-list", "zone:a", "-out", "o"}, // unknown kind
		{"-list", "domains:a", "-out", "o", "-max-change", "-1"},  // below 0
		{"-list", "domains:a", "-out", "o", "-max-change", "NaN"}, // no limit at all
		{"-list", "domains:a", "-out", "o", "-max-change", "+Inf"},
		{"-list", "domains:a", "-out", "o", "-min-change", "-1"},
	} {
		if _, _, err := blocklistRequest(args); err == nil {
			t.Errorf("%v taken", args)
		}
	}
}

func TestCmdBlocklistRefusal(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "ads%d.example.com\n", i)
		}
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(b.String()), 0o644)
		return p
	}
	out := filepath.Join(dir, "l.bin")
	if err := cmdBlocklist([]string{"-list", "domains:" + write("a.txt", 1000), "-out", out}); err != nil {
		t.Fatal(err)
	}
	err := cmdBlocklist([]string{"-list", "domains:" + write("b.txt", 300), "-out", out})
	var sce *blocklist.SizeChangeError
	if !errors.As(err, &sce) || !strings.Contains(err.Error(), "blocked 1000 → 300 (-70.0%)") {
		t.Fatalf("refusal: %v", err)
	}
	if err := cmdBlocklist([]string{"-list", "domains:" + filepath.Join(dir, "b.txt"), "-out", out, "-accept-change"}); err != nil {
		t.Fatal(err)
	}
}

// A build taken under the floor says so: "within 2%" alone would be false for a 5% change
// the floor let through.
func TestPrintBlocklistWithinFloor(t *testing.T) {
	r := &blocklist.Result{Out: "l.bin", File: blocklist.FileStats{Size: 9450}, Change: blocklist.SizeChange{Previous: "l.bin",
		Old: &blocklist.Size{Blocked: 1000, Bytes: 9000}, New: blocklist.Size{Blocked: 1050, Bytes: 9450}, MaxChange: 2, MinChange: 100}}
	var b strings.Builder
	printBlocklist(&b, r)
	if !strings.Contains(b.String(), "within 2% or 100 entries") {
		t.Errorf("printed %q", b.String())
	}
}
