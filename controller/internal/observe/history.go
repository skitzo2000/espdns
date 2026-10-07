// Package observe is the controller's side of the nodes' observability (docs/design.md,
// Observability, the dashboard): each node's /metrics read on the node list's poll (every
// 10 s) into a short history in memory, and its query log read with a cursor into a bounded
// buffer, for the Dashboard and Query log pages. Nothing is written to disk.
//
// The history keeps, per node, the change in each counter between two polls (a Point), not
// the counters: rates, shares and answer-time quantiles over any span are then sums of
// points, per node or over the fleet. A counter that goes down is a reboot (the uptime went
// down: everything counts from 0 again) or, for the query path's 32-bit counters, a wrap;
// anything else that goes down started over (a service restarted live) and counts from 0.
package observe

import (
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
)

const (
	// HistoryLen is how many points a node keeps: an hour at the node list's 10 s poll.
	HistoryLen = 360
	// Window is the span the dashboard sums over, and BinWidth its charts' step.
	Window   = time.Hour
	BinWidth = time.Minute
	// fresh: a point older than this isn't "now" (the node stopped answering).
	fresh = 35 * time.Second
)

// Bounds are the firmware's histogram buckets (firmware/main/stats.c ST_BUCKET_LE), in
// seconds. A node with other bounds is read onto these (each bound takes the count at the
// largest bound of the node's not past it).
var Bounds = [NB]float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
	0.25, 0.5, 1, 2.5, math.Inf(1)}

// NB is the number of buckets.
const NB = 15

// Results are the query results the firmware counts (espdns_queries_total{result}).
var Results = [NR]string{"cache", "forwarded", "hosted", "secondary", "blocked", "overridden", "refused",
	"servfail", "error", "notify", "dropped"}

// NR is the number of results.
const NR = 11

func resultIndex(r string) int {
	for i, s := range Results {
		if s == r {
			return i
		}
	}
	return -1
}

// Point is what a node did between two polls: each counter's change, over Secs seconds
// ending At. 32-bit fields: a poll's change can't come near 2^32 (saturated if it did).
type Point struct {
	At       time.Time
	Secs     float32
	Rebooted bool // the node booted in this span: its counts are from its boot on
	Results  [NR]uint32
	Latency  [NB]uint32 // queries answered in each bucket (not cumulative)
	Upstream [NB]uint32 // forwarder answers in each bucket, every forwarder
	UpQ      uint32     // forwarder attempts
	UpFail   uint32     // forwarder failures (no answer, or SERVFAIL)
	UpTime   uint32     // of the failures, no answer within the try's timeout
	Shed     uint32     // queries shed: the upstream query table, or a group's cap, full (SERVFAIL at once)
	Expired  uint32     // upstream queries that ended with no answer
	TCPRetry uint32     // truncated answers asked again over TCP
	SelErr   uint32     // the forward loop's select() errors
	Hits     uint32     // cache hits
	Misses   uint32     // cache misses
	BusyDNS  float32    // seconds the full clock was held answering queries
}

// raw is one /metrics read: the counters, each as the node sent it, and the gauges.
type raw struct {
	uptime   float64
	hasUp    bool
	results  [NR]float64
	hasRes   bool
	latency  [NB]float64            // per bucket
	upstream map[string][NB]float64 // per forwarder, per bucket
	upQ      map[string]float64
	upFail   map[string]float64
	upTime   map[string]float64
	shed     map[string]float64 // per group: default, zones
	expired  map[string]float64
	tcpRetry float64
	selErr   float64
	hits     float64
	misses   float64
	busy     map[string]float64
	gauges   Gauges
}

// Gauges are a node's last /metrics gauges: nil when the firmware doesn't send them.
type Gauges struct {
	Uptime      *float64 `json:"uptime_s"`
	HeapFree    *float64 `json:"heap_free"`     // internal RAM free
	HeapMin     *float64 `json:"heap_min_free"` // its low-water mark since boot
	PSRAMFree   *float64 `json:"psram_free"`
	PSRAMMin    *float64 `json:"psram_min_free"`
	PlanIntern  *float64 `json:"plan_internal"` // the memory plan's internal pool: planned
	CapIntern   *float64 `json:"cap_internal"`  // and what may be planned (board data)
	PlanPSRAM   *float64 `json:"plan_psram"`
	CapPSRAM    *float64 `json:"cap_psram"`
	MHzMax      *float64 `json:"mhz_max"`
	MHzIdle     *float64 `json:"mhz_idle"`
	DFS         *float64 `json:"dfs"`
	CacheItems  *float64 `json:"cache_entries"`
	CacheMax    *float64 `json:"cache_entries_max"`
	UpFailing   *float64 `json:"upstream_failing"`
	QueryLogCap *float64 `json:"querylog_capacity"`
	// The forward loop's table of upstream queries (memory.fwd_pending slots, a group's cap
	// half of them): outstanding now to the default forwarders and to the forward zones, and
	// the most at once since boot.
	FwdSlots    *float64 `json:"fwd_slots"`
	FwdCap      *float64 `json:"fwd_group_cap"`
	FwdInflight *float64 `json:"fwd_inflight"`
	FwdZones    *float64 `json:"fwd_inflight_zones"`
	FwdPeak     *float64 `json:"fwd_inflight_peak"`
}

func ptr(m fleet.Metrics, name string, kv ...string) *float64 {
	if v, ok := m.Value(name, kv...); ok && !math.IsNaN(v) && !math.IsInf(v, 0) {
		return &v
	}
	return nil
}

// buckets reads histogram name's buckets with the labels kv onto Bounds, per bucket.
func buckets(m fleet.Metrics, name string, kv ...string) ([NB]float64, bool) {
	type b struct{ le, n float64 }
	var bs []b
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if s.Name != name+"_bucket" || !labelsMatch(s.Labels, kv) {
				continue
			}
			le, ok := parseLE(s.Labels["le"])
			if ok {
				bs = append(bs, b{le, s.Value})
			}
		}
	}
	var out [NB]float64
	if len(bs) == 0 {
		return out, false
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].le < bs[j].le })
	var cum [NB]float64
	for i, bound := range Bounds {
		for _, x := range bs {
			if x.le <= bound*(1+1e-9) {
				cum[i] = x.n
			}
		}
	}
	prev := 0.0
	for i := range cum {
		out[i] = math.Max(0, cum[i]-prev)
		prev = math.Max(prev, cum[i])
	}
	return out, true
}

func labelsMatch(l map[string]string, kv []string) bool {
	for i := 0; i+1 < len(kv); i += 2 {
		if l[kv[i]] != kv[i+1] {
			return false
		}
	}
	return true
}

func parseLE(s string) (float64, bool) {
	if s == "+Inf" || s == "Inf" {
		return math.Inf(1), true
	}
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil
}

// readRaw takes what the history needs from a node's /metrics.
func readRaw(m fleet.Metrics) raw {
	r := raw{upstream: map[string][NB]float64{}, upQ: map[string]float64{}, upFail: map[string]float64{},
		upTime: map[string]float64{}, busy: map[string]float64{}}
	r.uptime, r.hasUp = m.Value("espdns_uptime_seconds")
	for res, v := range m.ByLabel("espdns_queries_total", "result") {
		if i := resultIndex(res); i >= 0 {
			r.results[i], r.hasRes = v, true
		}
	}
	r.latency, _ = buckets(m, "espdns_query_duration_seconds")
	ups := map[string]bool{}
	for _, f := range m.Families {
		for _, s := range f.Samples {
			if s.Name == "espdns_upstream_duration_seconds_bucket" {
				ups[s.Labels["upstream"]] = true
			}
		}
	}
	for u := range ups {
		r.upstream[u], _ = buckets(m, "espdns_upstream_duration_seconds", "upstream", u)
	}
	r.upQ = m.ByLabel("espdns_upstream_queries_total", "upstream")
	r.upFail = m.ByLabel("espdns_upstream_failures_total", "upstream")
	r.upTime = m.ByLabel("espdns_upstream_timeouts_total", "upstream")
	r.shed = m.ByLabel("espdns_fwd_shed_total", "group")
	r.expired = m.ByLabel("espdns_fwd_expired_total", "group")
	r.tcpRetry, _ = m.Value("espdns_fwd_tcp_retries_total")
	r.selErr, _ = m.Value("espdns_fwd_select_errors_total")
	r.hits, _ = m.Value("espdns_cache_hits_total")
	r.misses, _ = m.Value("espdns_cache_misses_total")
	r.busy = m.ByLabel("espdns_cpu_busy_seconds_total", "hold")
	g := &r.gauges
	if r.hasUp {
		g.Uptime = &r.uptime
	}
	g.HeapFree = ptr(m, "espdns_heap_free_bytes", "pool", "internal")
	g.HeapMin = ptr(m, "espdns_heap_min_free_bytes", "pool", "internal")
	g.PSRAMFree = ptr(m, "espdns_heap_free_bytes", "pool", "psram")
	g.PSRAMMin = ptr(m, "espdns_heap_min_free_bytes", "pool", "psram")
	g.PlanIntern = ptr(m, "espdns_memory_planned_bytes", "pool", "internal")
	g.CapIntern = ptr(m, "espdns_memory_capacity_bytes", "pool", "internal")
	g.PlanPSRAM = ptr(m, "espdns_memory_planned_bytes", "pool", "psram")
	g.CapPSRAM = ptr(m, "espdns_memory_capacity_bytes", "pool", "psram")
	g.MHzMax = ptr(m, "espdns_cpu_mhz", "clock", "max")
	g.MHzIdle = ptr(m, "espdns_cpu_mhz", "clock", "idle")
	g.DFS = ptr(m, "espdns_cpu_dfs")
	g.CacheItems = ptr(m, "espdns_cache_entries")
	g.CacheMax = ptr(m, "espdns_cache_entries_max")
	g.UpFailing = ptr(m, "espdns_upstream_failing")
	g.QueryLogCap = ptr(m, "espdns_querylog_capacity")
	g.FwdSlots = ptr(m, "espdns_fwd_slots")
	g.FwdCap = ptr(m, "espdns_fwd_group_cap")
	g.FwdInflight = ptr(m, "espdns_fwd_inflight", "group", "default")
	g.FwdZones = ptr(m, "espdns_fwd_inflight", "group", "zones")
	g.FwdPeak = ptr(m, "espdns_fwd_inflight_peak")
	return r
}

const two32 = 1 << 32

// Delta is how much a counter went up from prev to cur. rebooted: the node booted between
// them, so cur is all since its boot. A counter that went down otherwise wrapped at 2^32 if
// it was past 2^31 and is now under it (the query path's counters are 32-bit: a poll's
// change is far under 2^31); else it started over (a service restarted live), from 0.
func Delta(prev, cur float64, rebooted bool) float64 {
	switch {
	case math.IsNaN(cur) || cur < 0:
		return 0
	case rebooted || math.IsNaN(prev):
		return cur
	case cur >= prev:
		return cur - prev
	case prev >= two32/2 && prev < two32 && cur < two32/2:
		return cur + two32 - prev
	default:
		return cur
	}
}

func sat(v float64) uint32 {
	if v <= 0 || math.IsNaN(v) {
		return 0
	}
	if v >= math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(math.Round(v))
}

func sumDelta(prev, cur map[string]float64, rebooted bool) float64 {
	t := 0.0
	for k, v := range cur {
		p, ok := prev[k]
		if !ok {
			p = 0
		}
		t += Delta(p, v, rebooted)
	}
	return t
}

// point is the change from prev (read at pt) to cur (read at at); false when there is
// nothing to say (no queries counted: firmware without the counters).
func point(prev raw, pt time.Time, cur raw, at time.Time) (Point, bool) {
	if !cur.hasRes {
		return Point{}, false
	}
	p := Point{At: at}
	secs := at.Sub(pt).Seconds()
	p.Rebooted = cur.hasUp && prev.hasUp && cur.uptime < prev.uptime
	if p.Rebooted && cur.uptime < secs {
		secs = cur.uptime // the counts are from the boot on
	}
	if secs <= 0 {
		return Point{}, false
	}
	p.Secs = float32(secs)
	rb := p.Rebooted
	for i := range p.Results {
		p.Results[i] = sat(Delta(prev.results[i], cur.results[i], rb))
	}
	for i := range p.Latency {
		p.Latency[i] = sat(Delta(prev.latency[i], cur.latency[i], rb))
	}
	for u, bs := range cur.upstream {
		pb := prev.upstream[u]
		for i := range bs {
			p.Upstream[i] = sat(float64(p.Upstream[i]) + Delta(pb[i], bs[i], rb))
		}
	}
	p.UpQ = sat(sumDelta(prev.upQ, cur.upQ, rb))
	p.UpFail = sat(sumDelta(prev.upFail, cur.upFail, rb))
	p.UpTime = sat(sumDelta(prev.upTime, cur.upTime, rb))
	p.Shed = sat(sumDelta(prev.shed, cur.shed, rb))
	p.Expired = sat(sumDelta(prev.expired, cur.expired, rb))
	p.TCPRetry = sat(Delta(prev.tcpRetry, cur.tcpRetry, rb))
	p.SelErr = sat(Delta(prev.selErr, cur.selErr, rb))
	p.Hits = sat(Delta(prev.hits, cur.hits, rb))
	p.Misses = sat(Delta(prev.misses, cur.misses, rb))
	if v, ok := cur.busy["dns"]; ok {
		p.BusyDNS = float32(Delta(prev.busy["dns"], v, rb))
	}
	return p, true
}

// ring is a node's points, oldest first, at most HistoryLen.
type ring struct {
	buf  [HistoryLen]Point
	head int // the next slot written
	n    int
}

func (r *ring) add(p Point) {
	r.buf[r.head] = p
	r.head = (r.head + 1) % HistoryLen
	if r.n < HistoryLen {
		r.n++
	}
}

// each calls f on every point, oldest first.
func (r *ring) each(f func(*Point)) {
	start := (r.head - r.n + HistoryLen) % HistoryLen
	for i := 0; i < r.n; i++ {
		f(&r.buf[(start+i)%HistoryLen])
	}
}

func (r *ring) last() *Point {
	if r.n == 0 {
		return nil
	}
	return &r.buf[(r.head-1+HistoryLen)%HistoryLen]
}

// Totals is points summed.
type Totals struct {
	Secs     float64
	Results  [NR]uint64
	Latency  [NB]uint64
	Upstream [NB]uint64
	UpQ      uint64
	UpFail   uint64
	UpTime   uint64
	Shed     uint64
	Expired  uint64
	TCPRetry uint64
	SelErr   uint64
	Hits     uint64
	Misses   uint64
	BusyDNS  float64
	Reboots  int
}

func (t *Totals) add(p *Point) {
	t.Secs += float64(p.Secs)
	for i, v := range p.Results {
		t.Results[i] += uint64(v)
	}
	for i := range p.Latency {
		t.Latency[i] += uint64(p.Latency[i])
		t.Upstream[i] += uint64(p.Upstream[i])
	}
	t.UpQ += uint64(p.UpQ)
	t.UpFail += uint64(p.UpFail)
	t.UpTime += uint64(p.UpTime)
	t.Shed += uint64(p.Shed)
	t.Expired += uint64(p.Expired)
	t.TCPRetry += uint64(p.TCPRetry)
	t.SelErr += uint64(p.SelErr)
	t.Hits += uint64(p.Hits)
	t.Misses += uint64(p.Misses)
	t.BusyDNS += float64(p.BusyDNS)
	if p.Rebooted {
		t.Reboots++
	}
}

// merge adds o to t, as another node over the same span (Secs is kept: the span's, not the sum).
func (t *Totals) merge(o Totals) {
	secs := math.Max(t.Secs, o.Secs)
	for i := range t.Results {
		t.Results[i] += o.Results[i]
	}
	for i := range t.Latency {
		t.Latency[i] += o.Latency[i]
		t.Upstream[i] += o.Upstream[i]
	}
	t.UpQ += o.UpQ
	t.UpFail += o.UpFail
	t.UpTime += o.UpTime
	t.Shed += o.Shed
	t.Expired += o.Expired
	t.TCPRetry += o.TCPRetry
	t.SelErr += o.SelErr
	t.Hits += o.Hits
	t.Misses += o.Misses
	t.BusyDNS += o.BusyDNS
	t.Reboots += o.Reboots
	t.Secs = secs
}

// Blocked is every query blocked: by the blocklist (the name, or a CNAME in its answer:
// result blocked) and by the overrides (overridden).
func (t Totals) Blocked() uint64 {
	return t.Results[resultIndex("blocked")] + t.Results[resultIndex("overridden")]
}

// Blocks says whether a query log result is a block (Totals.Blocked's two).
func Blocks(result string) bool { return result == "blocked" || result == "overridden" }

// Queries is every query counted.
func (t Totals) Queries() uint64 {
	var n uint64
	for _, v := range t.Results {
		n += v
	}
	return n
}

// Quantile is the q-quantile (0-1) of per-bucket counts over Bounds, as Prometheus'
// histogram_quantile: linear within the bucket it falls in, the last finite bound past it.
// False with no observations.
func Quantile(counts [NB]uint64, q float64) (float64, bool) {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0, false
	}
	rank := q * float64(total)
	lo, below := 0.0, 0.0
	for i, c := range counts {
		n := below + float64(c)
		if n >= rank && c > 0 {
			if math.IsInf(Bounds[i], 1) {
				return lo, true
			}
			return lo + (Bounds[i]-lo)*(rank-below)/float64(c), true
		}
		lo, below = Bounds[i], n
		if math.IsInf(lo, 1) {
			lo = Bounds[NB-2]
		}
	}
	return Bounds[NB-2], true
}
