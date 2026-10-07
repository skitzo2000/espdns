package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// A config whose services don't fit the node's memory plan is refused before any node is
// touched: by what the node reports, else by its catalog board. A node the controller can't
// place (no memory in /status, a board it doesn't know) is left to refuse it itself.
func TestConfigPayloadsMemoryPlan(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.json")
	os.WriteFile(p, []byte(`{"name":"a"}`), 0o644) // every service
	f, _, err := configPayloads([]string{"192.0.2.10=" + p}, []string{"192.0.2.10"}, "../../../boards", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, st := range []release.NodeStatus{
		{Board: "p4-ip101", Image: "esp32p4-rev1"},
		{Board: "ws-s3-eth", Image: "esp32s3-octal"},
		{Board: "no-such-board"},
		{},
	} {
		if _, err := f(ctx, "192.0.2.10", st); err != nil {
			t.Fatalf("%s: %v", st.Board, err)
		}
	}
	small := memplan.Values(memplan.Keys{}, "esp32s3-octal", 8192)
	small.BlocklistKB = 4096 // more than the S3's PSRAM holds next to its cache
	st := release.NodeStatus{Board: "ws-s3-eth", Memory: &release.MemoryStatus{Board: small}}
	if _, err := f(ctx, "192.0.2.10", st); err == nil || !strings.Contains(err.Error(), "PSRAM: the services need") ||
		!strings.Contains(err.Error(), "as it reports") {
		t.Fatalf("a plan that doesn't fit: %v", err)
	}
	os.WriteFile(p, []byte(`{"name":"a","blocking":{"enabled":false}}`), 0o644)
	if f, _, err = configPayloads([]string{"192.0.2.10=" + p}, []string{"192.0.2.10"}, "../../../boards", ""); err != nil {
		t.Fatal(err)
	}
	st.Services = []release.ServiceStatus{{Name: "dns", State: "running"}}
	if _, err := f(ctx, "192.0.2.10", st); err != nil {
		t.Fatalf("the same board with blocking off: %v", err)
	}
}
