package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// A config with "querylog" is refused for a node whose firmware has no query log (no /status
// "querylog"): that firmware refuses the key.
func TestConfigPayloadsQueryLog(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	newer := release.NodeStatus{QueryLog: &release.QueryLogStatus{State: "running"}}
	for body, sets := range map[string]bool{
		`{"name":"a"}`:                     false,
		`{"querylog":{}}`:                  true,
		`{"querylog":{"client":"hidden"}}`: true,
		`{"querylog":{"enabled":false}}`:   true,
	} {
		p := filepath.Join(dir, "a.json")
		os.WriteFile(p, []byte(body), 0o644)
		f, _, err := configPayloads([]string{"192.0.2.10=" + p}, []string{"192.0.2.10"}, "", "")
		if err != nil {
			t.Fatal(body, err)
		}
		if _, err := f(ctx, "192.0.2.10", newer); err != nil {
			t.Fatalf("%s on firmware with the query log: %v", body, err)
		}
		_, err = f(ctx, "192.0.2.10", release.NodeStatus{})
		if sets != (err != nil) || sets && !strings.Contains(err.Error(), "update its firmware first") {
			t.Fatalf("%s on firmware from before the query log: %v", body, err)
		}
	}
}

func fakeHost(t *testing.T, n *fakenode.Node) string {
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// espdns querylog: what the node holds, then (-follow) what comes; lost entries said.
func TestQueryLogCommand(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	n.QueryLogCap = 3
	host := fakeHost(t, n)
	for i := 1; i <= 5; i++ {
		n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", "blocked", "NOERROR")
	}
	var out bytes.Buffer
	if err := runQueryLog(context.Background(), &fleet.Client{}, &out, host, queryLogOpts{}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "# 2 queries lost") || strings.Count(s, "blocked(list)") != 3 || !strings.Contains(s, "q5.example") ||
		strings.Contains(s, "q2.example") || !strings.Contains(s, "192.0.2.10") {
		t.Fatalf("%s", s)
	}

	// -follow: a second read finds what came since; -json is one object a line.
	out.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error)
	go func() {
		done <- runQueryLog(ctx, &fleet.Client{}, &out, host, queryLogOpts{cursor: 5, follow: true,
			every: 20 * time.Millisecond, json: true, pages: 2})
	}()
	time.Sleep(5 * time.Millisecond)
	n.LogQuery("192.0.2.12", "new.example", "AAAA", "cache", "NOERROR")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"qname":"new.example"`) {
		t.Fatalf("%s", out.String())
	}

	// Firmware from before the query log.
	old := fakenode.New("dns-b", [6]byte{2, 0, 0, 0, 0, 2}, "esp32p4-rev1", "p4-ip101", nil)
	old.NoObserve = true
	err := runQueryLog(context.Background(), &fleet.Client{}, &out, fakeHost(t, old), queryLogOpts{})
	if !errors.Is(err, fleet.ErrNotSupported) || !strings.Contains(err.Error(), "not supported") {
		t.Fatal(err)
	}
}

// espdns metrics: a summary of what /metrics says.
func TestMetricsSummary(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	host := fakeHost(t, n)
	n.LogQuery("192.0.2.10", "a.example", "A", "cache", "NOERROR")
	n.LogQuery("192.0.2.10", "b.example", "A", "blocked", "NOERROR")
	n.LogQuery("192.0.2.10", "c.example", "A", "servfail", "SERVFAIL")
	n.SetShed(3)
	m, err := (&fleet.Client{}).Metrics(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printMetrics(&out, host, m)
	s := out.String()
	for _, want := range []string{"healthy", "firmware 1 on p4-ip101", "queries 3", "cache 1", "blocked 1",
		"blocklist seq 1, 1000 entries", "querylog running", "query log 3 of 100",
		"forwarder 192.0.2.53: 1 asked, 1 failed (1 timed out)",
		"upstream queries: 0 in flight to the forwarders, 0 to forward zones (each at most 16), peak 1 of 32",
		"shed 3 (forwarders 3, zones 0), unanswered 1, TCP retries 0, select errors 0"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in\n%s", want, s)
		}
	}
}

// espdns querylog -follow waits out a node that reboots (it doesn't answer for a while), then
// reads its new boot's log from the start, saying so; with -json the notes go apart from the
// queries, which stay one JSON object a line.
func TestQueryLogFollowReboot(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	host := fakeHost(t, n)
	n.LogQuery("192.0.2.10", "before.example", "A", "cache", "NOERROR")
	n.DownFor = 60 * time.Millisecond
	var out, notes bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error)
	go func() {
		done <- runQueryLog(ctx, &fleet.Client{}, &out, host, queryLogOpts{follow: true, every: 10 * time.Millisecond,
			json: true, notes: &notes, pages: 40})
	}()
	time.Sleep(15 * time.Millisecond)
	n.Reboot()
	time.Sleep(100 * time.Millisecond) // back up
	n.LogQuery("192.0.2.11", "after.example", "A", "forwarded", "NOERROR")
	err := <-done
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"qname":"before.example"`) || !strings.Contains(out.String(), `"qname":"after.example"`) {
		t.Fatalf("queries:\n%s", out.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if !strings.HasPrefix(line, "{") {
			t.Fatalf("not a JSON object: %q", line)
		}
	}
	for _, want := range []string{"trying again", "answers again", "rebooted: its query log starts over"} {
		if !strings.Contains(notes.String(), want) {
			t.Errorf("no %q in the notes:\n%s", want, notes.String())
		}
	}

	// Not following, a node that doesn't answer is an error at once.
	n.Reboot()
	if err := runQueryLog(context.Background(), &fleet.Client{}, &out, host, queryLogOpts{}); err == nil {
		t.Fatal("no error from a node that is down")
	}
}
