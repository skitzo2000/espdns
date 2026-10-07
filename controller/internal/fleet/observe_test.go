package fleet_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

// The text the firmware's writer makes (firmware/tests/metrics_vector.txt, which its host
// tests check byte for byte) reads back as written.
func TestMetricsVector(t *testing.T) {
	raw, err := os.ReadFile("../../../firmware/tests/metrics_vector.txt")
	if err != nil {
		t.Fatal(err)
	}
	m, err := fleet.ParseMetrics(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := m.Value("espdns_zone_serial", "zone", "a\"b\\c\nd", "kind", "hosted"); !ok || v != 2026100401 {
		t.Errorf("zone serial %v %v", v, ok)
	}
	if f := m.Family("espdns_zone_serial"); f == nil || f.Type != "gauge" || f.Help != "Each zone's SOA serial." {
		t.Errorf("%+v", f)
	}
	if v, _ := m.Value("espdns_wifi_rssi_dbm"); v != -61 {
		t.Errorf("rssi %v", v)
	}
	if v, _ := m.Value("espdns_uptime_seconds"); math.Abs(v-3723.004005) > 1e-9 {
		t.Errorf("uptime %v", v)
	}
	h := m.Family("espdns_query_duration_seconds")
	if h == nil || h.Type != "histogram" || len(h.Samples) != 17 {
		t.Fatalf("%+v", h)
	}
	if v, _ := m.Value("espdns_query_duration_seconds_count"); v != 2 {
		t.Errorf("count %v", v)
	}
	if v, _ := m.Value("espdns_upstream_duration_seconds_sum", "upstream", "192.0.2.1"); math.Abs(v-1.2007) > 1e-9 {
		t.Errorf("sum %v", v)
	}
	if v, _ := m.Value("espdns_upstream_duration_seconds_bucket", "upstream", "192.0.2.1", "le", "+Inf"); v != 2 {
		t.Errorf("+Inf bucket %v", v)
	}
	// One in (0.0005, 0.001], one in (1, 2.5]: the median at the top of the first's bucket.
	if q, ok := m.Quantile("espdns_query_duration_seconds", 0.5); !ok || math.Abs(q-0.001) > 1e-9 {
		t.Errorf("p50 %v %v", q, ok)
	}
	if q, _ := m.Quantile("espdns_query_duration_seconds", 1); math.Abs(q-2.5) > 1e-9 {
		t.Errorf("p100 %v", q)
	}
	// The forwarders' timeouts and the forward loop's families (firmware #53).
	if f := m.Family("espdns_upstream_timeouts_total"); f == nil || f.Type != "counter" || len(f.Samples) != 2 {
		t.Errorf("%+v", f)
	}
	if v, _ := m.Value("espdns_fwd_shed_total", "group", "default"); v != 4 {
		t.Errorf("shed %v", v)
	}
	if v, _ := m.Value("espdns_fwd_zone_inflight", "zone", "lab.example.net"); v != 2 {
		t.Errorf("zone in flight %v", v)
	}
	if f := m.Family("espdns_fwd_inflight"); f == nil || f.Type != "gauge" || m.Sum("espdns_fwd_inflight") != 7 {
		t.Errorf("%+v", f)
	}
}

func TestParseMetrics(t *testing.T) {
	m, err := fleet.ParseMetrics("# a comment\nfoo_total 3\nfoo_total{x=\"1\"} 4 1700000000000\nbar NaN\nbaz +Inf\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if f := m.Family("foo_total"); f == nil || f.Type != "untyped" || len(f.Samples) != 2 || m.Sum("foo_total") != 7 {
		t.Errorf("%+v", m.Families)
	}
	if v, _ := m.Value("bar"); !math.IsNaN(v) {
		t.Errorf("bar %v", v)
	}
	if v, _ := m.Value("baz"); !math.IsInf(v, 1) {
		t.Errorf("baz %v", v)
	}
	if _, ok := m.Quantile("nothing", 0.5); ok {
		t.Error("a quantile of nothing")
	}
	for _, bad := range []string{"foo", "foo{x=\"1} 2", "foo{x} 2", "foo abc", "foo 1 2 3"} {
		if _, err := fleet.ParseMetrics(bad + "\n"); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// A fake node's /metrics and query log, read as the CLI and the dashboard read them: pages
// after a cursor, entries lost when the ring wrapped, a reboot starting the seqs over.
func TestQueryLogPaging(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	n.QueryLogCap = 10
	srv := httptest.NewServer(n)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := &fleet.Client{}
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", "forwarded", "NOERROR")
	}
	p, err := c.QueryLog(ctx, host, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 5 || p.Next != 5 || p.Lost != 0 || p.More || p.Oldest != 1 || p.Newest != 5 ||
		p.Capacity != 10 || p.State != "running" || p.Entries[0].QName != "q1.example" || *p.Entries[0].Client != "192.0.2.10" {
		t.Fatalf("%+v", p)
	}
	if p, _ = c.QueryLog(ctx, host, 3, 1); len(p.Entries) != 1 || p.Entries[0].Seq != 4 || p.Next != 4 || !p.More {
		t.Fatalf("%+v", p)
	}
	// Twelve more: the ring keeps 8-17; a reader at 5 lost 6 and 7.
	for i := 6; i <= 17; i++ {
		n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "AAAA", "cache", "NOERROR")
	}
	cur := fleet.QueryLogCursor{}
	if p, _, err = c.ReadQueryLog(ctx, host, &cur, 0); err != nil || len(p.Entries) != 10 || p.Lost != 7 {
		t.Fatalf("%+v %v", p, err)
	}
	if cur.Seq != 17 || cur.BootID != p.BootID {
		t.Fatalf("cursor %+v", cur)
	}
	if p, _ = c.QueryLog(ctx, host, 5, 0); p.Lost != 2 || p.Entries[0].Seq != 8 || p.Next != 17 {
		t.Fatalf("%+v", p)
	}
	// Up to date: nothing new.
	if p, restarted, err := c.ReadQueryLog(ctx, host, &cur, 0); err != nil || restarted || len(p.Entries) != 0 || cur.Seq != 17 {
		t.Fatalf("%+v %v %v", p, restarted, err)
	}
	// A reboot: the seqs start over under a new boot ID; the reader starts from the oldest.
	n.Do(func(n *fakenode.Node) { n.DownFor = 0 })
	n.Reboot()
	for i := 1; i <= 3; i++ {
		n.LogQuery("192.0.2.11", fmt.Sprintf("r%d.example", i), "A", "blocked", "NOERROR")
	}
	p, restarted, err := c.ReadQueryLog(ctx, host, &cur, 0)
	if err != nil || !restarted || len(p.Entries) != 3 || p.Entries[0].Seq != 1 || p.Entries[0].Rule != "list" || cur.Seq != 3 {
		t.Fatalf("%+v %v %v", p, restarted, err)
	}
	// A cursor past the newest reads from the oldest, flagged.
	if p, _ = c.QueryLog(ctx, host, 40, 0); !p.Reset || len(p.Entries) != 3 {
		t.Fatalf("%+v", p)
	}

	// The metrics count what it answered, the log or not.
	m, err := c.Metrics(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := m.Value("espdns_queries_total", "result", "blocked"); v != 3 {
		t.Errorf("blocked %v\n%s", v, m.Text)
	}
	if v, _ := m.Value("espdns_service_state", "service", "querylog", "state", "running"); v != 1 {
		t.Errorf("querylog service: %s", m.Text)
	}
	st, err := c.Status(ctx, host)
	if err != nil || st.QueryLog == nil || st.QueryLog.Newest != 3 || st.QueryLog.BootID != p.BootID {
		t.Fatalf("%+v %v", st.QueryLog, err)
	}
}

// Client privacy and the log off, from the node config; old firmware has neither endpoint.
func TestQueryLogSettings(t *testing.T) {
	n := fakenode.New("dns-a", [6]byte{2, 0, 0, 0, 0, 1}, "esp32p4-rev1", "p4-ip101", nil)
	srv := httptest.NewServer(n)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := &fleet.Client{}
	ctx := context.Background()
	setLog := func(q *nodecfg.QueryLog) { n.Do(func(n *fakenode.Node) { n.SetConfig(&nodecfg.Config{QueryLog: q}) }) }

	setLog(&nodecfg.QueryLog{Client: "subnet"})
	n.LogQuery("192.0.2.77", "a.example", "A", "forwarded", "NOERROR")
	setLog(&nodecfg.QueryLog{Client: "hidden"})
	n.LogQuery("192.0.2.77", "b.example", "A", "forwarded", "NOERROR")
	off := false
	setLog(&nodecfg.QueryLog{Enabled: &off})
	n.LogQuery("192.0.2.77", "c.example", "A", "forwarded", "NOERROR")
	p, err := c.QueryLog(ctx, host, 0, 0)
	if err != nil || len(p.Entries) != 2 || *p.Entries[0].Client != "192.0.2.0" || p.Entries[1].Client != nil ||
		p.State != "off" || p.Enabled {
		t.Fatalf("%+v %v", p, err)
	}
	m, _ := c.Metrics(ctx, host)
	if v, _ := m.Value("espdns_queries_total", "result", "forwarded"); v != 3 {
		t.Errorf("forwarded %v", v)
	}

	old := fakenode.New("dns-b", [6]byte{2, 0, 0, 0, 0, 2}, "esp32p4-rev1", "p4-ip101", nil)
	old.NoObserve = true
	osrv := httptest.NewServer(old)
	defer osrv.Close()
	ohost := strings.TrimPrefix(osrv.URL, "http://")
	if _, err := c.Metrics(ctx, ohost); !errors.Is(err, fleet.ErrNotSupported) {
		t.Errorf("metrics on old firmware: %v", err)
	}
	if _, err := c.QueryLog(ctx, ohost, 0, 0); !errors.Is(err, fleet.ErrNotSupported) {
		t.Errorf("querylog on old firmware: %v", err)
	}
	if st, err := c.Status(ctx, ohost); err != nil || st.QueryLog != nil {
		t.Errorf("%v %+v", err, st.QueryLog)
	}
}
