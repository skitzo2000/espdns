package web

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every health reason the firmware can report (firmware/main/health.c, REASON_NAME) is
// explained on the Nodes page (nodes.js, REASONS), so a degraded node always says why in
// words: "forwarders slow" (#60) among them.
func TestHealthReasonsExplained(t *testing.T) {
	c, err := os.ReadFile("../../firmware/main/health.c")
	if err != nil {
		t.Fatal(err)
	}
	src := string(c)
	start := strings.Index(src, "REASON_NAME[HR_NBITS] = {")
	if start < 0 {
		t.Fatal("no REASON_NAME in health.c")
	}
	end := strings.Index(src[start:], "};")
	names := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(src[start:start+end], -1)
	if len(names) < 20 {
		t.Fatalf("%d reason names read from health.c", len(names))
	}
	js, err := fs.ReadFile(Files, "nodes.js")
	if err != nil {
		t.Fatal(err)
	}
	r := string(js)
	r = r[strings.Index(r, "const REASONS = {"):]
	r = r[:strings.Index(r, "\n};")]
	for _, n := range names {
		name := n[1]
		key := regexp.MustCompile(`(?m)^\s*(?:"` + regexp.QuoteMeta(name) + `"|` + regexp.QuoteMeta(name) + `):\s*\["(warn|bad|info)", "[^"]+`)
		if !key.MatchString(r) {
			t.Errorf("health reason %q has no explanation in nodes.js REASONS", name)
		}
	}
}
