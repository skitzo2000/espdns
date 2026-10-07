package fakenode

// The fake node's observability, as firmware/main serves it: GET /metrics (a few of the
// node's families, in the Prometheus text format, from what it has logged), GET /querylog
// (a ring with a cursor, firmware qlog.h) and /status "querylog". NoObserve is firmware from
// before them: both endpoints 404, no "querylog" in /status or its services, and a config
// with "querylog" refused.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// observe is the node's query log and its counters.
type observe struct {
	bootID  string
	next    uint64 // the next entry's seq
	ring    []release.QueryEntry
	results map[string]uint64
	shed    uint64 // queries shed at the forward loop's caps (SetShed)
}

// QueryLogCapacity is how many queries a fake node's ring holds unless QueryLogCap says.
const QueryLogCapacity = 100

func (n *Node) obsInit() {
	if n.obs.bootID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		n.obs = observe{bootID: hex.EncodeToString(b), next: 1, results: map[string]uint64{}}
	}
}

// Reboot reboots it now (back after DownFor), as the controller's reboot does.
func (n *Node) Reboot() { n.Do(func(n *Node) { n.reboot() }) }

// SetConfig makes c the config it runs, as if pushed and applied live. Locked (in Do).
func (n *Node) SetConfig(c *nodecfg.Config) { n.cfg = c }

// obsReboot is a boot: the seqs start over, under a new boot ID. Locked.
func (n *Node) obsReboot() { n.obs = observe{} }

func (n *Node) capacity() int {
	if n.QueryLogCap > 0 {
		return n.QueryLogCap
	}
	return QueryLogCapacity
}

// querylogOn says whether the query log runs: its config has it on and the firmware has one.
func (n *Node) querylogOn() bool {
	if n.NoObserve || slices.Contains(n.Off, "querylog") {
		return false
	}
	q := n.cfg.QueryLog
	return q == nil || q.Enabled == nil || *q.Enabled
}

func (n *Node) querylogClient() string {
	if q := n.cfg.QueryLog; q != nil && q.Client != "" {
		return q.Client
	}
	return "full"
}

// LogQuery is a query the node answered: counted, and logged while the query log runs (none
// while it reboots).
// client is the client's address; result one of the firmware's (cache, forwarded,
// hosted, blocked, ...).
func (n *Node) LogQuery(client, qname, qtype, result, rcode string) {
	n.Do(func(n *Node) {
		if n.isDown() {
			return // rebooting: it answers nothing
		}
		n.obsInit()
		n.obs.results[result]++
		if !n.querylogOn() {
			return
		}
		e := release.QueryEntry{Seq: n.obs.next, UptimeMS: uint64(time.Since(n.boot).Milliseconds()), Transport: "udp",
			QName: qname, QType: qtype, Result: result, RCode: rcode, LatencyUS: 1000}
		switch n.querylogClient() {
		case "full":
			e.Client = &client
		case "subnet":
			s := client[:strings.LastIndexByte(client, '.')+1] + "0"
			e.Client = &s
		}
		if result == "blocked" {
			e.Rule = "list"
		}
		ms := time.Now().UnixMilli()
		e.Time = &ms
		n.obs.next++
		n.obs.ring = append(n.obs.ring, e)
		if len(n.obs.ring) > n.capacity() {
			n.obs.ring = n.obs.ring[len(n.obs.ring)-n.capacity():]
		}
	})
}

// SetCount sets the count of queries with this result, as /metrics sends it (a test of a
// 32-bit counter about to wrap, or one that wrapped).
func (n *Node) SetCount(result string, v uint64) {
	n.Do(func(n *Node) {
		n.obsInit()
		n.obs.results[result] = v
	})
}

// SetShed sets how many queries to the default forwarders were shed at the forward loop's
// caps (espdns_fwd_shed_total{group="default"}).
func (n *Node) SetShed(v uint64) {
	n.Do(func(n *Node) {
		n.obsInit()
		n.obs.shed = v
	})
}

// oldest is the oldest seq held (next while empty). Locked.
func (n *Node) oldest() uint64 {
	if len(n.obs.ring) == 0 {
		return n.obs.next
	}
	return n.obs.ring[0].Seq
}

// observeConfig refuses what this firmware doesn't take. Locked.
func (n *Node) observeConfig(c *nodecfg.Config) error {
	if n.NoObserve && c.SetsQueryLog() {
		return errors.New(`config refused: unknown key "querylog"`)
	}
	return nil
}

// observeStatus adds /status "querylog". Locked.
func (n *Node) observeStatus(st map[string]any) {
	if n.NoObserve {
		return
	}
	n.obsInit()
	state := "off"
	if n.querylogOn() {
		state = "running"
	}
	st["querylog"] = map[string]any{"enabled": n.querylogOn(), "state": state, "client": n.querylogClient(),
		"capacity": n.capacity(), "entries": len(n.obs.ring), "oldest": n.oldest(), "newest": n.obs.next - 1,
		"boot_id": n.obs.bootID}
}

// serviceNames are its services as its firmware lists them.
func (n *Node) serviceNames() []string {
	s := []string{"dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking"}
	if !n.NoObserve {
		s = append(s, "querylog")
	}
	return s
}

// serveObserve answers /metrics and /querylog; false for another path. Locked.
func (n *Node) serveObserve(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/metrics" && r.URL.Path != "/querylog" {
		return false
	}
	if n.NoObserve {
		http.NotFound(w, r)
		return true
	}
	n.obsInit()
	if r.URL.Path == "/metrics" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, n.metrics())
		return true
	}
	q := r.URL.Query()
	var cursor uint64
	var err1, err2 error
	if s := q.Get("cursor"); s != "" {
		cursor, err1 = strconv.ParseUint(s, 10, 64)
	}
	limit := 100
	if s := q.Get("limit"); s != "" {
		limit, err2 = strconv.Atoi(s)
	}
	if err1 != nil || err2 != nil || limit < 1 {
		http.Error(w, "cursor and limit: whole numbers, limit 1 or more", http.StatusBadRequest)
		return true
	}
	limit = min(limit, release.QueryLogLimit)
	p := release.QueryLogPage{BootID: n.obs.bootID, Enabled: n.querylogOn(), State: "off", Client: n.querylogClient(),
		Capacity: uint32(n.capacity()), Oldest: n.oldest(), Newest: n.obs.next - 1, Cursor: cursor,
		UptimeMS: uint64(time.Since(n.boot).Milliseconds()), Entries: []release.QueryEntry{}}
	if p.Enabled {
		p.State = "running"
	}
	now := time.Now().UnixMilli()
	p.Time = &now
	// As qlog.c's ql_cursor.
	from := cursor + 1
	switch {
	case cursor >= n.obs.next:
		from, p.Reset = n.oldest(), true
	case cursor+1 < n.oldest():
		from, p.Lost = n.oldest(), n.oldest()-(cursor+1)
	}
	p.Next = from - 1
	for _, e := range n.obs.ring {
		if e.Seq >= from && len(p.Entries) < limit {
			p.Entries = append(p.Entries, e)
			p.Next = e.Seq
		}
	}
	p.More = p.Next+1 < n.obs.next
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
	return true
}

// metrics is its /metrics: the families the firmware's have, from what it holds.
func (n *Node) metrics() string {
	var b strings.Builder
	fam := func(name, typ, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ) }
	fam("espdns_build_info", "gauge", "The firmware, chip image and board: always 1.")
	fmt.Fprintf(&b, "espdns_build_info{version=%q,image=%q,board=%q,idf=\"v5.5.5\"} 1\n", n.Version, n.Image, n.Board)
	fam("espdns_uptime_seconds", "gauge", "Time since boot.")
	fmt.Fprintf(&b, "espdns_uptime_seconds %.6f\n", time.Since(n.boot).Seconds())
	fam("espdns_health_state", "gauge", "The node's health state: 1 for the one it is in.")
	for _, s := range []string{"booting", "healthy", "degraded", "no network", "fault", "updating"} {
		v := 0
		if s == n.state {
			v = 1
		}
		fmt.Fprintf(&b, "espdns_health_state{state=%q} %d\n", s, v)
	}
	fam("espdns_queries_total", "counter", "Queries by what answered them.")
	var total uint64
	for _, r := range []string{"cache", "forwarded", "hosted", "secondary", "blocked", "overridden", "refused",
		"servfail", "error", "notify", "dropped"} {
		fmt.Fprintf(&b, "espdns_queries_total{result=%q} %d\n", r, n.obs.results[r])
		total += n.obs.results[r]
	}
	fam("espdns_queries_received_total", "counter", "DNS messages received, by transport.")
	fmt.Fprintf(&b, "espdns_queries_received_total{transport=\"udp\"} %d\nespdns_queries_received_total{transport=\"tcp\"} 0\n", total)
	// The firmware's buckets (stats.c ST_BUCKET_LE): every query takes 1 ms, as logged, and a
	// forwarder 10 ms.
	les := []string{"0.0001", "0.00025", "0.0005", "0.001", "0.0025", "0.005", "0.01", "0.025", "0.05", "0.1",
		"0.25", "0.5", "1", "2.5", "+Inf"}
	hist := func(name, labels string, n uint64, at int, each float64) {
		for i, le := range les {
			v := n
			if i < at {
				v = 0
			}
			fmt.Fprintf(&b, "%s_bucket{%sle=%q} %d\n", name, labels, le, v)
		}
		if labels != "" {
			labels = "{" + strings.TrimSuffix(labels, ",") + "}"
		}
		fmt.Fprintf(&b, "%s_sum%s %.6f\n%s_count%s %d\n", name, labels, float64(n)*each, name, labels, n)
	}
	fam("espdns_query_duration_seconds", "histogram", "Time to answer a query.")
	hist("espdns_query_duration_seconds", "", total, 3, 0.001)
	fwd, fail := n.obs.results["forwarded"]+n.obs.results["servfail"], n.obs.results["servfail"]
	fam("espdns_upstream_queries_total", "counter", "Attempts at each forwarder (each server tried, each retry).")
	fmt.Fprintf(&b, "espdns_upstream_queries_total{upstream=\"192.0.2.53\"} %d\n", fwd)
	fam("espdns_upstream_failures_total", "counter", "Failures at each forwarder: no answer, or SERVFAIL.")
	fmt.Fprintf(&b, "espdns_upstream_failures_total{upstream=\"192.0.2.53\"} %d\n", fail)
	// A servfail here is a forwarder that timed out: its upstream query ended unanswered.
	fam("espdns_upstream_timeouts_total", "counter", "Attempts at each forwarder with no answer within the try's timeout.")
	fmt.Fprintf(&b, "espdns_upstream_timeouts_total{upstream=\"192.0.2.53\"} %d\n", fail)
	fam("espdns_upstream_duration_seconds", "histogram", "Time each forwarder took to answer.")
	hist("espdns_upstream_duration_seconds", `upstream="192.0.2.53",`, fwd-fail, 6, 0.01)
	// The forward loop: a P4's table (memory.fwd_pending 32), nothing outstanding between
	// queries.
	fam("espdns_fwd_slots", "gauge", "Upstream queries the node may have outstanding at once (memory.fwd_pending).")
	fmt.Fprintf(&b, "espdns_fwd_slots 32\n")
	fam("espdns_fwd_group_cap", "gauge", "The most of them one group may hold.")
	fmt.Fprintf(&b, "espdns_fwd_group_cap 16\n")
	fam("espdns_fwd_inflight", "gauge", "Upstream queries outstanding now.")
	fmt.Fprintf(&b, "espdns_fwd_inflight{group=\"default\"} 0\nespdns_fwd_inflight{group=\"zones\"} 0\n")
	fam("espdns_fwd_inflight_peak", "gauge", "The most upstream queries outstanding at once since boot.")
	fmt.Fprintf(&b, "espdns_fwd_inflight_peak %d\n", min(fwd, 16))
	fam("espdns_fwd_shed_total", "counter", "Queries answered SERVFAIL at once: their group, or the table, was at its cap.")
	fmt.Fprintf(&b, "espdns_fwd_shed_total{group=\"default\"} %d\nespdns_fwd_shed_total{group=\"zones\"} 0\n", n.obs.shed)
	fam("espdns_fwd_expired_total", "counter", "Upstream queries that ended with no answer.")
	fmt.Fprintf(&b, "espdns_fwd_expired_total{group=\"default\"} %d\nespdns_fwd_expired_total{group=\"zones\"} 0\n", fail)
	fam("espdns_fwd_tcp_retries_total", "counter", "Truncated answers asked again over TCP.")
	fmt.Fprintf(&b, "espdns_fwd_tcp_retries_total 0\n")
	fam("espdns_fwd_select_errors_total", "counter", "Times the forward loop's select() failed.")
	fmt.Fprintf(&b, "espdns_fwd_select_errors_total 0\n")
	fam("espdns_cache_hits_total", "counter", "Lookups answered from the cache.")
	fmt.Fprintf(&b, "espdns_cache_hits_total %d\n", n.obs.results["cache"])
	fam("espdns_cache_misses_total", "counter", "Lookups not in the cache.")
	fmt.Fprintf(&b, "espdns_cache_misses_total %d\n", fwd)
	fam("espdns_heap_free_bytes", "gauge", "Heap free now, per pool (observed; nothing is sized from it).")
	fmt.Fprintf(&b, "espdns_heap_free_bytes{pool=\"internal\"} 98304\nespdns_heap_free_bytes{pool=\"psram\"} 4194304\n")
	fam("espdns_memory_capacity_bytes", "gauge", "What the services may plan in each pool (board data).")
	fmt.Fprintf(&b, "espdns_memory_capacity_bytes{pool=\"internal\"} 131072\nespdns_memory_capacity_bytes{pool=\"psram\"} 8388608\n")
	fam("espdns_memory_planned_bytes", "gauge", "What the running services' plan takes in each pool.")
	fmt.Fprintf(&b, "espdns_memory_planned_bytes{pool=\"internal\"} 65536\nespdns_memory_planned_bytes{pool=\"psram\"} 4194304\n")
	fam("espdns_cpu_mhz", "gauge", "The CPU clock: max (while working) and idle (what it drops to).")
	fmt.Fprintf(&b, "espdns_cpu_mhz{clock=\"max\"} 240\nespdns_cpu_mhz{clock=\"idle\"} 80\n")
	fam("espdns_cpu_busy_seconds_total", "counter", "Time the full clock was held.")
	fmt.Fprintf(&b, "espdns_cpu_busy_seconds_total{hold=\"dns\"} %.6f\nespdns_cpu_busy_seconds_total{hold=\"work\"} 0.000000\n",
		float64(total)*0.001)
	fam("espdns_blocklist_entries", "gauge", "Entries in the list in use.")
	fmt.Fprintf(&b, "espdns_blocklist_entries{list=\"blocklist\"} %d\nespdns_blocklist_entries{list=\"overrides\"} %d\n",
		n.list.Entries, n.ovr.Entries)
	fam("espdns_blocklist_seq", "gauge", "The release seq of the list in use (0: none).")
	fmt.Fprintf(&b, "espdns_blocklist_seq{list=\"blocklist\"} %d\nespdns_blocklist_seq{list=\"overrides\"} %d\n",
		n.list.Seq, n.ovr.Seq)
	fam("espdns_service_state", "gauge", "Each service, with its state: 1.")
	for _, s := range n.services() {
		fmt.Fprintf(&b, "espdns_service_state{service=%q,state=%q} 1\n", s["name"], s["state"])
	}
	fam("espdns_querylog_capacity", "gauge", "Queries the query log's ring holds.")
	fmt.Fprintf(&b, "espdns_querylog_capacity %d\n", n.capacity())
	fam("espdns_querylog_entries", "gauge", "Queries in the ring now.")
	fmt.Fprintf(&b, "espdns_querylog_entries %d\n", len(n.obs.ring))
	return b.String()
}
