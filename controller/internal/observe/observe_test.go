package observe

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

func TestDelta(t *testing.T) {
	for _, c := range []struct {
		prev, cur float64
		rebooted  bool
		want      float64
	}{
		{10, 25, false, 15},
		{10, 10, false, 0},
		{two32 - 5, 3, false, 8},     // a 32-bit counter wrapped
		{100, 5, false, 5},           // started over (a service restarted live)
		{two32 + 100, 50, false, 50}, // a 64-bit count that went down: started over
		{two32/2 - 1, 3, false, 3},   // under 2^31: not a wrap
		{5000, 7, true, 7},           // a reboot: all since the boot
		{5000, 9000, true, 9000},     // a reboot, more since it than before
		{math.NaN(), 4, false, 4},    // none before
		{4, math.NaN(), false, 0},
	} {
		if got := Delta(c.prev, c.cur, c.rebooted); got != c.want {
			t.Errorf("Delta(%v, %v, %v) = %v, want %v", c.prev, c.cur, c.rebooted, got, c.want)
		}
	}
}

func TestQuantile(t *testing.T) {
	var c [NB]uint64
	if _, ok := Quantile(c, .5); ok {
		t.Error("no observations: a quantile")
	}
	c[3] = 10 // all in (0.0005, 0.001]
	if v, _ := Quantile(c, .5); math.Abs(v-0.00075) > 1e-12 {
		t.Errorf("p50 = %v", v)
	}
	c[NB-1] = 90 // past the last bound: the last bound
	if v, _ := Quantile(c, .95); v != 2.5 {
		t.Errorf("p95 past the last bound = %v", v)
	}
}

// A node's buckets read onto the firmware's, whatever its bounds.
func TestBucketsResample(t *testing.T) {
	m, err := fleet.ParseMetrics("# TYPE h histogram\nh_bucket{le=\"0.001\"} 4\nh_bucket{le=\"0.1\"} 6\nh_bucket{le=\"+Inf\"} 7\n")
	if err != nil {
		t.Fatal(err)
	}
	b, ok := buckets(m, "h")
	if !ok || b[3] != 4 || b[9] != 2 || b[NB-1] != 1 {
		t.Errorf("buckets %v", b)
	}
	var n float64
	for _, v := range b {
		n += v
	}
	if n != 7 {
		t.Errorf("total %v", n)
	}
}

// fake serves n, counting the requests for each path.
type fake struct {
	n    *fakenode.Node
	host string
	hits map[string]*atomic.Int64
}

func newFake(t *testing.T, name string, last byte) *fake {
	f := &fake{n: fakenode.New(name, [6]byte{2, 0, 0, 0, 0, last}, "esp32p4-rev1", "p4-ip101", nil),
		hits: map[string]*atomic.Int64{"/metrics": {}, "/querylog": {}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := f.hits[r.URL.Path]; c != nil {
			c.Add(1)
		}
		f.n.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f.host = strings.TrimPrefix(srv.URL, "http://")
	return f
}

func (f *fake) node() nodes.Node {
	return nodes.Node{ID: f.n.ID(), Addr: f.host, Hostname: f.n.Name, Online: true,
		Status: map[string]any{"health": map[string]any{"state": "healthy", "reasons": []any{}}}}
}

// clock is a store whose time is set by the test.
func clocked() (*Store, *time.Time) {
	s := New(&fleet.Client{})
	now := time.Now()
	s.now = func() time.Time { return now }
	return s, &now
}

func nodeView(t *testing.T, d Dashboard, key string) NodeView {
	t.Helper()
	for _, n := range d.Nodes {
		if n.Key == key {
			return n
		}
	}
	t.Fatalf("no node %s in %+v", key, d.Nodes)
	return NodeView{}
}

func near(p *float64, want float64) bool { return p != nil && math.Abs(*p-want) < 1e-9 }

// Rates and shares from two polls, per node and summed over the fleet.
func TestScrapeRates(t *testing.T) {
	a, b := newFake(t, "dns-a", 1), newFake(t, "dns-b", 2)
	s, now := clocked()
	ctx := context.Background()
	s.Scrape(ctx, []nodes.Node{a.node(), b.node()})
	for i := range 10 {
		res := []string{"cache", "cache", "cache", "cache", "cache", "cache", "blocked", "overridden", "forwarded", "forwarded"}[i]
		a.n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", res, "NOERROR")
	}
	b.n.LogQuery("192.0.2.11", "x.example", "AAAA", "servfail", "SERVFAIL")
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node(), b.node()})
	d := s.Dashboard()

	na := nodeView(t, d, a.n.ID())
	if na.Now == nil || !near(na.Now.QPS, 1) || na.Now.Queries != 10 {
		t.Fatalf("node a now: %+v", na.Now)
	}
	r := na.Now
	// Blocked counts the overrides' blocks as well as the blocklist's
	if !near(r.BlockedShare, .2) || r.Blocked != 2 || !near(r.CacheHitRate, .75) || r.Results["cache"] != 6 {
		t.Errorf("node a: blocked %v, hit rate %v, results %v", *r.BlockedShare, *r.CacheHitRate, r.Results)
	}
	if r.P50 == nil || *r.P50 <= 0.5 || *r.P50 > 1 { // every query 1 ms: in (0.5, 1] ms
		t.Errorf("p50 %v", r.P50)
	}
	if r.UpP95 == nil || *r.UpP95 <= 5 || *r.UpP95 > 10 { // the forwarder 10 ms: in (5, 10] ms
		t.Errorf("upstream p95 %v", r.UpP95)
	}
	if na.Gauges.MHzMax == nil || *na.Gauges.MHzMax != 240 || na.Gauges.HeapFree == nil {
		t.Errorf("gauges %+v", na.Gauges)
	}
	if na.Health != "healthy" || na.Metrics.State != "ok" {
		t.Errorf("health %q, metrics %+v", na.Health, na.Metrics)
	}

	f := d.Fleet
	if !near(f.Now.QPS, 1.1) || f.Now.Queries != 11 || f.Now.ServFail != 1 || f.Now.UpFailures != 1 || f.Now.UpQueries != 3 {
		t.Errorf("fleet now: %+v", f.Now)
	}
	if !near(f.Hour.QPS, 1.1) || f.Reading != 2 || f.Nodes != 2 {
		t.Errorf("fleet hour: %+v", f)
	}
	last := f.QPS[len(f.QPS)-1]
	if !near(last, 1.1) {
		t.Errorf("fleet qps series ends %v", last)
	}
	if lb := f.Blocked[len(f.Blocked)-1]; !near(lb, .2) || f.Now.Blocked != 2 {
		t.Errorf("fleet blocked: series ends %v, now %d", lb, f.Now.Blocked)
	}
	if f.QPS[0] != nil {
		t.Errorf("an hour ago: %v", *f.QPS[0])
	}

	// A node that stops answering is no longer "now", but stays in the hour.
	*now = now.Add(time.Minute)
	d = s.Dashboard()
	if nodeView(t, d, a.n.ID()).Now != nil || d.Fleet.Now.QPS != nil || !near(d.Fleet.Hour.QPS, 1.1) {
		t.Errorf("a minute on: now %+v, hour %v", d.Fleet.Now, d.Fleet.Hour.QPS)
	}
}

// The forward loop's metrics (firmware #53): the table's gauges as the node sends them, and
// its counters as changes between polls, per node and over the fleet.
func TestScrapeForwardLoop(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	s, now := clocked()
	ctx := context.Background()
	s.Scrape(ctx, []nodes.Node{a.node()})
	a.n.LogQuery("192.0.2.10", "slow.example", "A", "servfail", "SERVFAIL")
	a.n.LogQuery("192.0.2.10", "fine.example", "A", "forwarded", "NOERROR")
	a.n.SetShed(7)
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node()})
	d := s.Dashboard()
	v := nodeView(t, d, a.n.ID())
	g := v.Gauges
	if !near(g.FwdSlots, 32) || !near(g.FwdCap, 16) || !near(g.FwdInflight, 0) || !near(g.FwdZones, 0) ||
		!near(g.FwdPeak, 2) {
		t.Errorf("gauges %+v", g)
	}
	r := v.Now
	if r == nil || r.FwdShed != 7 || r.UpTimeouts != 1 || r.FwdExpired != 1 || r.TCPRetries != 0 || r.SelectErrors != 0 {
		t.Fatalf("now %+v", r)
	}
	if v.Hour.FwdShed != 7 || d.Fleet.Now.FwdShed != 7 || d.Fleet.Hour.UpTimeouts != 1 {
		t.Errorf("hour %+v, fleet %+v", v.Hour, d.Fleet.Now)
	}
	// Nothing more: the next poll's change is none.
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node()})
	if r := nodeView(t, s.Dashboard(), a.n.ID()).Now; r == nil || r.FwdShed != 0 || r.UpTimeouts != 0 {
		t.Errorf("a quiet poll: %+v", r)
	}
}

// The firmware's own text (firmware/tests/metrics_vector.txt, written by its metrics.c):
// every forward loop family it sends is read.
func TestReadForwardVector(t *testing.T) {
	b, err := os.ReadFile("../../../firmware/tests/metrics_vector.txt")
	if err != nil {
		t.Fatal(err)
	}
	m, err := fleet.ParseMetrics(string(b))
	if err != nil {
		t.Fatal(err)
	}
	r := readRaw(m)
	g := r.gauges
	if !near(g.FwdSlots, 32) || !near(g.FwdCap, 16) || !near(g.FwdInflight, 4) || !near(g.FwdZones, 3) ||
		!near(g.FwdPeak, 17) {
		t.Errorf("gauges %+v", g)
	}
	if r.shed["default"] != 4 || r.shed["zones"] != 1 || r.expired["default"] != 2 || r.tcpRetry != 6 || r.selErr != 1 {
		t.Errorf("counters: shed %v, expired %v, tcp %v, select %v", r.shed, r.expired, r.tcpRetry, r.selErr)
	}
	if r.upTime["192.0.2.1"] != 1 || r.upTime["192.0.2.2"] != 0 || r.upFail["192.0.2.2"] != 1 {
		t.Errorf("timeouts %v, failures %v", r.upTime, r.upFail)
	}
	// From nothing to it: all of it counted (the vector has no queries: as if it had).
	r.hasRes = true
	p, ok := point(raw{}, time.Unix(0, 0), r, time.Unix(10, 0))
	if !ok || p.Shed != 5 || p.Expired != 2 || p.UpTime != 1 || p.TCPRetry != 6 || p.SelErr != 1 {
		t.Errorf("point %+v %v", p, ok)
	}
}

// A 32-bit counter that wraps between two polls counts what it went up by.
func TestScrapeWrap(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	s, now := clocked()
	ctx := context.Background()
	a.n.SetCount("cache", two32-4)
	s.Scrape(ctx, []nodes.Node{a.node()})
	a.n.SetCount("cache", 6)
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node()})
	r := nodeView(t, s.Dashboard(), a.n.ID()).Now
	if r == nil || r.Results["cache"] != 10 || !near(r.QPS, 1) {
		t.Fatalf("after a wrap: %+v", r)
	}
}

// A reboot: the counters start over, so the point is what was counted since the boot (no
// negative or huge rate), and the query log is read again from its new boot.
func TestScrapeReboot(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.DownFor = 20 * time.Millisecond
	s, now := clocked()
	ctx := context.Background()
	for i := range 50 {
		a.n.LogQuery("192.0.2.10", fmt.Sprintf("before%d.example", i), "A", "cache", "NOERROR")
	}
	s.Scrape(ctx, []nodes.Node{a.node()})
	s.Scrape(ctx, []nodes.Node{a.node()})
	a.n.Reboot()
	time.Sleep(40 * time.Millisecond)
	a.n.LogQuery("192.0.2.10", "after.example", "A", "blocked", "NOERROR")
	a.n.LogQuery("192.0.2.10", "after2.example", "A", "cache", "NOERROR")
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node()})
	d := s.Dashboard()
	v := nodeView(t, d, a.n.ID())
	if v.Now == nil || v.Now.Queries != 2 || v.Now.Reboots != 1 || v.Now.Results["blocked"] != 1 {
		t.Fatalf("after a reboot: %+v", v.Now)
	}
	if v.Hour.Queries != 2 { // the first two polls had nothing between them
		t.Errorf("hour: %d queries", v.Hour.Queries)
	}
	if v.QueryLog.Restarts != 1 || v.QueryLog.Read != 52 {
		t.Errorf("query log %+v", v.QueryLog)
	}
	l := s.Log(Filter{Name: "after"})
	if l.Matched != 2 || l.Entries[0].QName != "after2.example" {
		t.Errorf("after the reboot: %+v", l.Entries)
	}
}

// Firmware from before /metrics and the query log: shown as such, the node list's QPS
// passed on, and asked again only after a while.
func TestScrapeOldFirmware(t *testing.T) {
	a := newFake(t, "dns-old", 1)
	a.n.NoObserve = true
	s, now := clocked()
	ctx := context.Background()
	n := a.node()
	q := 3.5
	n.QPS = &q
	s.Scrape(ctx, []nodes.Node{n})
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{n})
	v := nodeView(t, s.Dashboard(), a.n.ID())
	if v.Metrics.State != "unsupported" || v.QueryLog.State != "unsupported" || !near(v.StatusQPS, 3.5) || v.Now != nil {
		t.Errorf("old firmware: %+v", v)
	}
	if a.hits["/metrics"].Load() != 1 || a.hits["/querylog"].Load() != 1 {
		t.Errorf("asked %d and %d times", a.hits["/metrics"].Load(), a.hits["/querylog"].Load())
	}
	*now = now.Add(retryUnsupported)
	s.Scrape(ctx, []nodes.Node{n})
	if a.hits["/metrics"].Load() != 2 {
		t.Errorf("not asked again after %v", retryUnsupported)
	}
	if l := s.Log(Filter{}); len(l.Nodes) != 1 || l.Nodes[0].State != "unsupported" {
		t.Errorf("log nodes %+v", l.Nodes)
	}
}

// A node that doesn't answer its /status isn't read; one no longer listed is forgotten.
func TestScrapeOnlyAnswering(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	s, _ := clocked()
	n := a.node()
	n.Online, n.Error = false, "timeout"
	s.Scrape(context.Background(), []nodes.Node{n})
	if a.hits["/metrics"].Load() != 0 {
		t.Error("read a node that didn't answer")
	}
	if d := s.Dashboard(); len(d.Nodes) != 1 || d.Nodes[0].Online {
		t.Errorf("nodes %+v", d.Nodes)
	}
	s.Scrape(context.Background(), nil)
	if d := s.Dashboard(); len(d.Nodes) != 0 {
		t.Errorf("forgotten node still there: %+v", d.Nodes)
	}
}

// The query log: two nodes merged by time, the filters, follow, and the top names.
func TestQueryLog(t *testing.T) {
	a, b := newFake(t, "dns-a", 1), newFake(t, "dns-b", 2)
	s, now := clocked()
	ctx := context.Background()
	a.n.LogQuery("192.0.2.10", "one.example", "A", "cache", "NOERROR")
	time.Sleep(2 * time.Millisecond)
	b.n.LogQuery("192.0.2.20", "ads.example", "A", "blocked", "NOERROR")
	time.Sleep(2 * time.Millisecond)
	a.n.LogQuery("192.0.2.11", "Two.Example", "AAAA", "forwarded", "NOERROR")
	time.Sleep(2 * time.Millisecond)
	b.n.LogQuery("192.0.2.20", "ads.example", "AAAA", "overridden", "NOERROR")
	s.Scrape(ctx, []nodes.Node{a.node(), b.node()})

	l := s.Log(Filter{})
	if l.Held != 4 || len(l.Entries) != 4 {
		t.Fatalf("held %d: %+v", l.Held, l.Entries)
	}
	var names []string
	for _, e := range l.Entries {
		names = append(names, e.QName)
	}
	if strings.Join(names, " ") != "ads.example Two.Example ads.example one.example" {
		t.Errorf("by time, newest first: %v", names)
	}
	for f, want := range map[*Filter]int{
		{Node: a.n.ID()}: 2, {Client: "192.0.2.2"}: 2, {Name: "two"}: 1, {Result: "blocked"}: 1,
		{Result: "overridden"}: 1, {QType: "aaaa"}: 2, {Limit: 1}: 1, {Result: "blocked", QType: "A"}: 1,
	} {
		if got := len(s.Log(*f).Entries); got != want {
			t.Errorf("filter %+v: %d, want %d", *f, got, want)
		}
	}
	last := l.Last
	a.n.LogQuery("192.0.2.10", "three.example", "A", "cache", "NOERROR")
	*now = now.Add(10 * time.Second)
	s.Scrape(ctx, []nodes.Node{a.node(), b.node()})
	if f := s.Log(Filter{After: last}); len(f.Entries) != 1 || f.Entries[0].QName != "three.example" {
		t.Errorf("follow after %d: %+v", last, f.Entries)
	}

	top := s.Top("")
	if top.Entries != 5 || top.Blocks != 2 || len(top.Blocked) != 1 || top.Blocked[0] != (TopName{"ads.example", 2}) ||
		top.Queried[0] != (TopName{"ads.example", 2}) {
		t.Errorf("top %+v", top)
	}
	if top := s.Top(a.n.ID()); top.Entries != 3 || top.Blocks != 0 {
		t.Errorf("top of a %+v", top)
	}
}

// A node's client setting made stricter masks what the controller already holds of it
// too; nothing comes back when it is made looser.
func TestQueryLogPrivacy(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	s, _ := clocked()
	ctx := context.Background()
	a.n.LogQuery("192.0.2.10", "one.example", "A", "cache", "NOERROR")
	s.Scrape(ctx, []nodes.Node{a.node()})
	if e := s.Log(Filter{}).Entries[0]; e.Client == nil || *e.Client != "192.0.2.10" {
		t.Fatalf("full: %v", e.Client)
	}
	set := func(mode string) {
		a.n.Do(func(n *fakenode.Node) {
			n.SetConfig(&nodecfg.Config{Name: "dns-a", QueryLog: &nodecfg.QueryLog{Client: mode}})
		})
	}
	set("subnet")
	s.Scrape(ctx, []nodes.Node{a.node()})
	if e := s.Log(Filter{}).Entries[0]; e.Client == nil || *e.Client != "192.0.2.0" {
		t.Errorf("subnet: %v", e.Client)
	}
	set("hidden")
	a.n.LogQuery("192.0.2.10", "two.example", "A", "cache", "NOERROR")
	s.Scrape(ctx, []nodes.Node{a.node()})
	for _, e := range s.Log(Filter{}).Entries {
		if e.Client != nil {
			t.Errorf("hidden: %s has %s", e.QName, *e.Client)
		}
	}
	if n := len(s.Log(Filter{Client: "192"}).Entries); n != 0 {
		t.Errorf("a hidden client matched: %d", n)
	}
	set("full")
	s.Scrape(ctx, []nodes.Node{a.node()})
	if e := s.Log(Filter{Name: "one"}).Entries[0]; e.Client != nil {
		t.Errorf("looser: came back as %s", *e.Client)
	}
	// An entry the node sent unmasked under a stricter setting is masked to it anyway.
	p := release.QueryLogPage{BootID: "x", Client: "subnet", Entries: []release.QueryEntry{{Seq: 1, QName: "x.example",
		Client: ptrS("198.51.100.7")}}}
	s.AddPage(a.n.ID(), p, false, nil, fleet.QueryLogCursor{BootID: "x", Seq: 1}, time.Now())
	if e := s.Log(Filter{Name: "x.example"}).Entries[0]; *e.Client != "198.51.100.0" {
		t.Errorf("masked as it came: %s", *e.Client)
	}
}

func ptrS(s string) *string { return &s }

// The buffer holds at most LogCap entries, the oldest dropped first; a node holding more
// than a poll reads is behind, and read on at the next.
func TestQueryLogBounded(t *testing.T) {
	s, now := clocked()
	s.nodes["n"] = &nodeState{key: "n"}
	var es []release.QueryEntry
	for i := 1; i <= LogCap+500; i++ {
		ms := now.UnixMilli() + int64(i)
		es = append(es, release.QueryEntry{Seq: uint64(i), Time: &ms, QName: fmt.Sprintf("q%d.example", i), Result: "cache"})
	}
	if more := s.AddPage("n", release.QueryLogPage{BootID: "b", Client: "full", Entries: es, More: true}, false, nil,
		fleet.QueryLogCursor{}, *now); !more {
		t.Error("more not passed on")
	}
	l := s.Log(Filter{Limit: 5000})
	if l.Held != LogCap || len(l.Entries) != 1000 || l.Entries[0].QName != fmt.Sprintf("q%d.example", LogCap+500) {
		t.Errorf("held %d, %d shown, newest %s", l.Held, len(l.Entries), l.Entries[0].QName)
	}
	if s.Top("").Entries != LogCap {
		t.Error("top counts more than held")
	}
	if !s.nodes["n"].ql.Behind {
		t.Error("not behind")
	}
	if l := s.Log(Filter{Name: "q1.example"}); l.Matched != 0 {
		t.Errorf("the oldest kept: %+v", l.Entries)
	}
}

// The pages a busy node holds are read in one poll, up to pagesPerPoll.
func TestQueryLogPages(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.QueryLogCap = 3000
	s, _ := clocked()
	s.Scrape(context.Background(), []nodes.Node{a.node()}) // the first read: where its log is
	for i := range 2500 {
		a.n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", "cache", "NOERROR")
	}
	a.hits["/querylog"].Store(0)
	s.Scrape(context.Background(), []nodes.Node{a.node()})
	if v := s.Log(Filter{}); v.Held != 2500 || a.hits["/querylog"].Load() != 3 || s.nodes[a.n.ID()].ql.Behind {
		t.Errorf("held %d in %d pages", v.Held, a.hits["/querylog"].Load())
	}
}

// The first read of a node's log (the controller started) starts at its newest
// firstEntries, one page: not every entry its ring holds, and the older ones not lost.
func TestQueryLogFirstRead(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.QueryLogCap = 4000
	for i := range 3500 {
		a.n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", "cache", "NOERROR")
	}
	s, _ := clocked()
	s.Scrape(context.Background(), []nodes.Node{a.node()})
	q := s.nodes[a.n.ID()].ql
	if v := s.Log(Filter{}); v.Held != firstEntries || a.hits["/querylog"].Load() != 2 || q.Lost != 0 ||
		q.Skipped != 3500-firstEntries || q.Behind || v.Entries[0].QName != "q3499.example" {
		t.Errorf("held %d in %d reads: %+v", v.Held, a.hits["/querylog"].Load(), q)
	}
	for _, c := range []struct {
		oldest, newest, seq, skipped uint64
	}{{1, 0, 0, 0}, {1, 10, 0, 0}, {5, 900, 4, 0}, {1, 5000, 4000, 4000}, {4500, 5000, 4499, 0}, {0, 0, 0, 0}} {
		cur, sk := firstCursor(release.QueryLogPage{BootID: "b", Oldest: c.oldest, Newest: c.newest})
		if cur.Seq != c.seq || sk != c.skipped || cur.BootID != "b" {
			t.Errorf("oldest %d newest %d: from %d, %d skipped", c.oldest, c.newest, cur.Seq, sk)
		}
	}
}

// A node listed twice (one ID: in settings.json at an old address, offline, and found over
// mDNS at its new one) is read once, at the address that answers, whichever sorts first.
func TestScrapeOneIDTwoAddresses(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.LogQuery("192.0.2.10", "one.example", "A", "cache", "NOERROR")
	for _, old := range []string{"0.0.0.1:1", "255.255.255.255:1"} {
		s, _ := clocked()
		gone := nodes.Node{ID: a.n.ID(), Addr: old, Error: "no answer", Status: map[string]any{}}
		s.Scrape(context.Background(), []nodes.Node{gone, a.node()})
		s.Scrape(context.Background(), []nodes.Node{a.node(), gone})
		d := s.Dashboard()
		if len(d.Nodes) != 1 || d.Nodes[0].Addr != a.host || !d.Nodes[0].Online || d.Nodes[0].Metrics.State != "ok" ||
			s.Log(Filter{}).Held != 1 {
			t.Errorf("old address %s: %+v", old, d.Nodes)
		}
	}
}

// A node dropped from the list and listed again (offline past the node list's prune) is
// read on from where it was: what the buffer holds of it isn't read again.
func TestQueryLogRelisted(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.LogQuery("192.0.2.10", "one.example", "A", "cache", "NOERROR")
	s, _ := clocked()
	ctx := context.Background()
	s.Scrape(ctx, []nodes.Node{a.node()})
	s.Scrape(ctx, nil)
	a.n.LogQuery("192.0.2.10", "two.example", "A", "cache", "NOERROR")
	s.Scrape(ctx, []nodes.Node{a.node()})
	if v := s.Log(Filter{}); v.Held != 2 {
		t.Errorf("held %d: %+v", v.Held, v.Entries)
	}
	if len(s.cursors) != 0 {
		t.Errorf("a cursor kept for a listed node: %v", s.cursors)
	}
	// One gone whose entries the buffer no longer holds isn't remembered.
	s.Scrape(ctx, nil)
	if len(s.cursors) != 1 {
		t.Fatalf("cursors %v", s.cursors)
	}
	s.log = logRing{}
	s.Scrape(ctx, nil)
	if len(s.cursors) != 0 {
		t.Errorf("cursors %v", s.cursors)
	}
}

// Follow with an ID from another run of the controller (its IDs started over) reads from
// the start, not from that ID on.
func TestQueryLogRun(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	a.n.LogQuery("192.0.2.10", "one.example", "A", "cache", "NOERROR")
	s, _ := clocked()
	s.Scrape(context.Background(), []nodes.Node{a.node()})
	v := s.Log(Filter{})
	if v.Run == "" || len(s.Log(Filter{After: 100, Run: v.Run}).Entries) != 0 ||
		len(s.Log(Filter{After: 100, Run: "another"}).Entries) != 1 {
		t.Errorf("run %q", v.Run)
	}
}

// The pages' reads while the store is written (go test -race).
func TestStoreConcurrent(t *testing.T) {
	a, b := newFake(t, "dns-a", 1), newFake(t, "dns-b", 2)
	s := New(&fleet.Client{})
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 20 {
			a.n.LogQuery("192.0.2.10", fmt.Sprintf("q%d.example", i), "A", "cache", "NOERROR")
			b.n.LogQuery("192.0.2.20", fmt.Sprintf("q%d.example", i), "A", "blocked", "NOERROR")
			list := []nodes.Node{a.node(), b.node()}
			if i%5 == 4 {
				list = list[:1]
			}
			s.Scrape(ctx, list)
		}
	}()
	for {
		select {
		case <-done:
			if v := s.Log(Filter{}); v.Held == 0 {
				t.Error("nothing read")
			}
			return
		default:
			s.Dashboard()
			s.Log(Filter{Name: "q"})
			s.Top("")
		}
	}
}

// The history keeps an hour: HistoryLen points.
func TestHistoryBounded(t *testing.T) {
	var r ring
	at := time.Now()
	for i := range HistoryLen + 10 {
		r.add(Point{At: at.Add(time.Duration(i) * time.Second), Secs: 1})
	}
	n := 0
	var first time.Time
	r.each(func(p *Point) {
		if n == 0 {
			first = p.At
		}
		n++
	})
	if n != HistoryLen || !first.Equal(at.Add(10*time.Second)) || !r.last().At.Equal(at.Add(time.Duration(HistoryLen+9)*time.Second)) {
		t.Errorf("%d points from %v", n, first)
	}
}

// Asked: the names and clients picked, counted in one pass, with their blocks and last
// time, the most asked first; a nil func picks none.
func TestAsked(t *testing.T) {
	a := newFake(t, "dns-a", 1)
	s, _ := clocked()
	ctx := context.Background()
	s.Scrape(ctx, []nodes.Node{a.node()})
	a.n.LogQuery("192.0.2.10", "Ads.Example", "A", "blocked", "NOERROR")
	a.n.LogQuery("192.0.2.10", "ads.example", "A", "blocked", "NOERROR")
	a.n.LogQuery("192.0.2.11", "ads.example", "AAAA", "cache", "NOERROR")
	a.n.LogQuery("192.0.2.11", "www.example", "A", "forwarded", "NOERROR")
	a.n.LogQuery("192.0.2.12", "other.test", "A", "forwarded", "NOERROR")
	s.Scrape(ctx, []nodes.Node{a.node()})

	names, clients := s.Asked(func(n string) bool { return strings.Contains(n, "example") },
		func(c string) bool { return c != "192.0.2.12" })
	if len(names) != 2 || names[0].Value != "ads.example" || names[0].Queries != 3 || names[0].Blocked != 2 ||
		names[0].Last.IsZero() || names[1].Value != "www.example" || names[1].Blocked != 0 {
		t.Errorf("names: %+v", names)
	}
	if len(clients) != 2 || clients[0].Value != "192.0.2.10" || clients[0].Queries != 2 || clients[0].Blocked != 2 ||
		clients[1].Value != "192.0.2.11" || clients[1].Queries != 2 {
		t.Errorf("clients: %+v", clients)
	}
	names, clients = s.Asked(nil, nil)
	if len(names) != 0 || len(clients) != 0 {
		t.Errorf("nil picks: %v %v", names, clients)
	}
}
