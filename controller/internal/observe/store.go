package observe

import (
	"context"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

const (
	// readTimeout bounds each read of a node (/metrics, a /querylog page).
	readTimeout = 8 * time.Second
	// pagesPerPoll: at most this many /querylog pages of release.QueryLogLimit a node is read
	// per poll (5000 queries in 10 s); a node with more is Behind and read on at the next.
	pagesPerPoll = 5
	// firstEntries: the first read of a node's query log (the controller started, or the node
	// is new to it) starts at its newest this many entries, not at the oldest it holds: a
	// node's ring can be far larger than the controller's buffer, and reading all of it
	// from every node at once is load on their HTTP servers for entries dropped anyway.
	firstEntries = release.QueryLogLimit
	// retryUnsupported: firmware without /metrics or /querylog is asked again this often
	// (an update brings them), not at every poll.
	retryUnsupported = 5 * time.Minute
)

// Store holds what the controller has read of each node's /metrics and query log.
type Store struct {
	Client *fleet.Client
	now    func() time.Time

	// run names this run of the store: IDs start over with it, so a reader following with
	// an ID from another run reads again from the start.
	run string

	mu     sync.Mutex
	nodes  map[string]*nodeState
	log    logRing
	nextID uint64
	// cursors: the query log cursors of nodes no longer listed whose entries the buffer
	// still holds, so a node listed again (it was offline past the node list's prune) is
	// read on from where it was, not again (duplicates).
	cursors map[string]fleet.QueryLogCursor
}

type nodeState struct {
	key, addr, name, id string
	online              bool
	health              string
	reasons             []string
	statusQPS           *float64
	statusHeap          *float64

	prev    raw
	prevAt  time.Time
	hasPrev bool
	hist    ring
	gauges  Gauges
	metrics QLState // State and Error only: how reading /metrics goes
	mRetry  time.Time

	cur     fleet.QueryLogCursor
	ql      QLState
	qlRetry time.Time
}

// New is an empty store reading nodes with client.
func New(client *fleet.Client) *Store {
	return &Store{Client: client, now: time.Now, nodes: map[string]*nodeState{}, cursors: map[string]fleet.QueryLogCursor{},
		run: strconv.FormatInt(time.Now().UnixNano(), 36)}
}

// Key is how the store names a node: its ID, else its address.
func Key(n nodes.Node) string {
	if n.ID != "" {
		return n.ID
	}
	return n.Addr
}

// Run reads the nodes each time the node list sends them (after each of its polls), until
// ctx ends. A send while a read runs waits for the next.
func (s *Store) Run(ctx context.Context, polled <-chan []nodes.Node) {
	for {
		select {
		case <-ctx.Done():
			return
		case list := <-polled:
			s.Scrape(ctx, list)
		}
	}
}

// answered: the node list's last poll of n had its /status.
func answered(n nodes.Node) bool { return n.Online && n.Error == "" && n.Status != nil }

// Scrape reads every node of list that answered its /status (its /metrics and new query
// log entries) and forgets the nodes no longer listed. A node listed twice (one ID at two
// addresses: in settings.json at its old one, found over mDNS at its new) is read once, at
// the address that answered.
func (s *Store) Scrape(ctx context.Context, list []nodes.Node) {
	byKey := map[string]nodes.Node{}
	var order []string
	for _, n := range list {
		k := Key(n)
		o, dup := byKey[k]
		if !dup {
			order = append(order, k)
		}
		if !dup || answered(n) && !answered(o) || answered(n) == answered(o) && n.LastSeen.After(o.LastSeen) {
			byKey[k] = n
		}
	}
	s.mu.Lock()
	keep := map[string]bool{}
	var todo []*nodeState
	for _, k := range order {
		n := byKey[k]
		keep[k] = true
		st := s.nodes[k]
		if st == nil {
			st = &nodeState{key: k, cur: s.cursors[k]}
			delete(s.cursors, k)
			s.nodes[k] = st
		}
		st.addr, st.id, st.online = n.Addr, n.ID, n.Online
		st.name = n.Hostname
		if st.name == "" {
			st.name = n.Addr
		}
		st.health, st.reasons = health(n.Status)
		st.statusQPS = n.QPS
		st.statusHeap = nil
		if v, ok := n.Status["heap_free"].(float64); ok {
			st.statusHeap = &v
		}
		if answered(n) {
			todo = append(todo, st)
		}
	}
	for k, st := range s.nodes {
		if !keep[k] {
			if st.cur.BootID != "" {
				s.cursors[k] = st.cur
			}
			delete(s.nodes, k)
		}
	}
	if len(s.cursors) > 0 {
		held := map[string]bool{}
		s.log.each(func(e *Entry) { held[e.Node] = true })
		for k := range s.cursors {
			if !held[k] {
				delete(s.cursors, k)
			}
		}
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, st := range todo {
		wg.Add(1)
		go func(st *nodeState) {
			defer wg.Done()
			s.readMetrics(ctx, st)
			s.readLog(ctx, st)
		}(st)
	}
	wg.Wait()
}

// health is a /status's health state and reasons (older firmware: its degraded flag).
func health(st map[string]any) (string, []string) {
	if st == nil {
		return "", nil
	}
	if h, ok := st["health"].(map[string]any); ok {
		state, _ := h["state"].(string)
		var rs []string
		if a, ok := h["reasons"].([]any); ok {
			for _, r := range a {
				if s, ok := r.(string); ok {
					rs = append(rs, s)
				}
			}
		}
		if state != "" {
			return state, rs
		}
	}
	if d, _ := st["degraded"].(bool); d {
		return "degraded", []string{"degraded"}
	}
	return "answering", nil
}

func (s *Store) readMetrics(ctx context.Context, st *nodeState) {
	s.mu.Lock()
	addr, skip := st.addr, s.now().Before(st.mRetry)
	s.mu.Unlock()
	if skip {
		return
	}
	c, cancel := context.WithTimeout(ctx, readTimeout)
	m, err := s.Client.Metrics(c, addr)
	cancel()
	s.AddMetrics(st.key, m, err, s.now())
}

// AddMetrics takes one /metrics read of the node (err: the read failed) at at.
func (s *Store) AddMetrics(key string, m fleet.Metrics, err error, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.nodes[key]
	if st == nil {
		return // forgotten while it was read
	}
	switch {
	case errors.Is(err, fleet.ErrNotSupported):
		st.metrics = QLState{State: "unsupported"}
		st.mRetry = at.Add(retryUnsupported)
		st.hasPrev = false
		return
	case err != nil:
		st.metrics = QLState{State: "error", Error: err.Error()}
		return // the next read's point spans the gap
	}
	st.metrics = QLState{State: "ok", LastRead: at}
	r := readRaw(m)
	st.gauges = r.gauges
	if st.hasPrev {
		if p, ok := point(st.prev, st.prevAt, r, at); ok {
			st.hist.add(p)
		}
	}
	st.prev, st.prevAt, st.hasPrev = r, at, true
}

func (s *Store) readLog(ctx context.Context, st *nodeState) {
	s.mu.Lock()
	addr, cur, skip := st.addr, st.cur, s.now().Before(st.qlRetry)
	s.mu.Unlock()
	if skip {
		return
	}
	if cur.BootID == "" {
		// The first read: one entry, for where the log is, then on from its newest
		// firstEntries.
		c, cancel := context.WithTimeout(ctx, readTimeout)
		p, err := s.Client.QueryLog(c, addr, 0, 1)
		cancel()
		if err != nil {
			s.AddPage(st.key, p, false, err, cur, s.now())
			return
		}
		var skipped uint64
		cur, skipped = firstCursor(p)
		s.mu.Lock()
		st.ql.Skipped += skipped
		s.mu.Unlock()
	}
	for i := 0; i < pagesPerPoll; i++ {
		c, cancel := context.WithTimeout(ctx, readTimeout)
		p, restarted, err := s.Client.ReadQueryLog(c, addr, &cur, release.QueryLogLimit)
		cancel()
		more := s.AddPage(st.key, p, restarted, err, cur, s.now())
		if err != nil || !more {
			return
		}
	}
}

// firstCursor is where a first read of a node's log starts, from a page that says where
// its log is: after the newest firstEntries it holds (the older ones skipped, not lost).
func firstCursor(p release.QueryLogPage) (fleet.QueryLogCursor, uint64) {
	from := uint64(0) // the oldest held
	if p.Oldest > 0 {
		from = p.Oldest - 1
	}
	var skipped uint64
	if p.Newest > firstEntries && p.Newest-firstEntries > from {
		skipped = p.Newest - firstEntries - from
		from = p.Newest - firstEntries
	}
	return fleet.QueryLogCursor{BootID: p.BootID, Seq: from}, skipped
}

// AddPage takes one /querylog page of the node: restarted (it rebooted since the last
// page), err (the read failed), cur the cursor after it. It says whether the node holds
// more already (read on).
func (s *Store) AddPage(key string, p release.QueryLogPage, restarted bool, err error, cur fleet.QueryLogCursor, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.nodes[key]
	if st == nil {
		return false
	}
	q := &st.ql
	switch {
	case errors.Is(err, fleet.ErrNotSupported):
		*q = QLState{State: "unsupported"}
		st.qlRetry = at.Add(retryUnsupported)
		return false
	case err != nil:
		q.State, q.Error = "error", err.Error()
		return false
	}
	if q.Client != "" && strictness(p.Client) > strictness(q.Client) || q.Client == "" && p.Client != "full" {
		// Stricter than what was read before: what the buffer holds of this node is
		// masked to it as well, as the node masks its ring.
		s.log.each(func(e *Entry) {
			if e.Node == key {
				e.Client = mask(e.Client, p.Client)
			}
		})
	}
	st.cur = cur
	q.State, q.Error, q.Enabled, q.Client, q.Capacity, q.LastRead = "ok", "", p.Enabled, p.Client, p.Capacity, at
	q.Lost += p.Lost
	if restarted || p.Reset {
		q.Restarts++
	}
	q.Behind = p.More
	for _, e := range p.Entries {
		e.Client = mask(e.Client, p.Client) // never more than the node's setting says
		s.nextID++
		q.Read++
		s.log.add(Entry{ID: s.nextID, Node: key, At: e.When(p, at), Estimated: e.Time == nil, QueryEntry: e})
	}
	return p.More
}

// ---- the dashboard ----

// Rates is what a span's points say.
type Rates struct {
	Secs         float64           `json:"secs"` // the span the points cover
	Queries      uint64            `json:"queries"`
	QPS          *float64          `json:"qps"`
	Results      map[string]uint64 `json:"results"`
	CacheHitRate *float64          `json:"cache_hit_rate"` // cache hits / lookups
	Blocked      uint64            `json:"blocked"`        // blocked by the blocklist or the overrides
	BlockedShare *float64          `json:"blocked_share"`  // blocked / queries
	P50          *float64          `json:"p50_ms"`         // time to answer
	P95          *float64          `json:"p95_ms"`
	UpP50        *float64          `json:"upstream_p50_ms"` // forwarders' answer time
	UpP95        *float64          `json:"upstream_p95_ms"`
	UpQueries    uint64            `json:"upstream_queries"`
	UpFailures   uint64            `json:"upstream_failures"`
	UpFailShare  *float64          `json:"upstream_failure_share"`
	UpTimeouts   uint64            `json:"upstream_timeouts"` // of the failures, no answer in the try's timeout
	FwdShed      uint64            `json:"fwd_shed"`          // queries shed at the upstream query table's caps
	FwdExpired   uint64            `json:"fwd_expired"`       // upstream queries that ended unanswered
	TCPRetries   uint64            `json:"tcp_retries"`       // truncated answers asked again over TCP
	SelectErrors uint64            `json:"select_errors"`     // the forward loop's select() errors
	ServFail     uint64            `json:"servfail"`
	Dropped      uint64            `json:"dropped"`
	Reboots      int               `json:"reboots"`
	BusyShare    *float64          `json:"busy_share,omitempty"` // of the time, the full clock held for DNS
}

func f64(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}

func share(a, b uint64) *float64 {
	if b == 0 {
		return nil
	}
	return f64(float64(a) / float64(b))
}

func ms(counts [NB]uint64, q float64) *float64 {
	if v, ok := Quantile(counts, q); ok {
		return f64(v * 1000)
	}
	return nil
}

func rates(t Totals) Rates {
	r := Rates{Secs: t.Secs, Queries: t.Queries(), Results: map[string]uint64{}, UpQueries: t.UpQ,
		UpFailures: t.UpFail, UpTimeouts: t.UpTime, FwdShed: t.Shed, FwdExpired: t.Expired, TCPRetries: t.TCPRetry,
		SelectErrors: t.SelErr, Reboots: t.Reboots}
	if t.Secs > 0 {
		r.QPS = f64(float64(r.Queries) / t.Secs)
		r.BusyShare = f64(math.Min(1, t.BusyDNS/t.Secs))
	}
	for i, n := range Results {
		r.Results[n] = t.Results[i]
	}
	r.ServFail, r.Dropped = t.Results[resultIndex("servfail")], t.Results[resultIndex("dropped")]
	r.CacheHitRate = share(t.Hits, t.Hits+t.Misses)
	r.Blocked = t.Blocked()
	r.BlockedShare = share(r.Blocked, r.Queries)
	r.P50, r.P95 = ms(t.Latency, .5), ms(t.Latency, .95)
	r.UpP50, r.UpP95 = ms(t.Upstream, .5), ms(t.Upstream, .95)
	r.UpFailShare = share(t.UpFail, t.UpQ)
	return r
}

// Series is a chart's values, one per bin (null: no points in it).
type Series []*float64

// Dashboard is the fleet and each node, now (the last poll) and over Window.
type Dashboard struct {
	Now      time.Time  `json:"now"`
	Window   float64    `json:"window_s"`
	BinWidth float64    `json:"bin_s"`
	Bins     int        `json:"bins"`
	Fleet    FleetView  `json:"fleet"`
	Nodes    []NodeView `json:"nodes"`
}

// FleetView is every node summed: QPS is the nodes' rates added.
type FleetView struct {
	Now      Rates  `json:"now"`
	Hour     Rates  `json:"hour"`
	Nodes    int    `json:"nodes"`
	Reading  int    `json:"reading"` // nodes whose /metrics read
	QPS      Series `json:"qps"`
	Blocked  Series `json:"blocked_qps"`
	P95      Series `json:"p95_ms"`
	UpP95    Series `json:"upstream_p95_ms"`
	UpFail   Series `json:"upstream_failures"`
	HitRate  Series `json:"cache_hit_rate"`
	ServFail Series `json:"servfail"`
}

// NodeView is one node.
type NodeView struct {
	Key     string   `json:"key"`
	ID      string   `json:"id"`
	Addr    string   `json:"addr"`
	Name    string   `json:"name"`
	Online  bool     `json:"online"`
	Health  string   `json:"health"`
	Reasons []string `json:"reasons"`
	// Metrics: how reading its /metrics goes (State "unsupported": firmware from before it).
	Metrics QLState `json:"metrics"`
	// StatusQPS is the node list's (from /status queries.total), for firmware without /metrics.
	StatusQPS  *float64 `json:"status_qps"`
	StatusHeap *float64 `json:"status_heap_free"`
	Gauges     Gauges   `json:"gauges"`
	Now        *Rates   `json:"now"` // the last point, if fresh
	Hour       Rates    `json:"hour"`
	QPS        Series   `json:"qps"`
	QueryLog   QLState  `json:"querylog"`
}

// Dashboard sums the history.
func (s *Store) Dashboard() Dashboard {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	nb := int(Window / BinWidth)
	start := now.Add(-Window)
	d := Dashboard{Now: now, Window: Window.Seconds(), BinWidth: BinWidth.Seconds(), Bins: nb}
	fleetBins := make([]Totals, nb)
	fleetQPS := make([]float64, nb)
	fleetHas := make([]bool, nb)
	fleetBlocked := make([]float64, nb)
	var fleetHour, fleetNow Totals
	var qpsHour, qpsNow float64
	anyHour, anyNow := false, false

	keys := make([]string, 0, len(s.nodes))
	for k := range s.nodes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return s.nodes[keys[i]].addr < s.nodes[keys[j]].addr })
	for _, k := range keys {
		st := s.nodes[k]
		v := NodeView{Key: k, ID: st.id, Addr: st.addr, Name: st.name, Online: st.online, Health: st.health,
			Reasons: st.reasons, Metrics: st.metrics, StatusQPS: st.statusQPS, StatusHeap: st.statusHeap,
			Gauges: st.gauges, QueryLog: st.ql, QPS: make(Series, nb)}
		if v.Reasons == nil {
			v.Reasons = []string{}
		}
		bins := make([]Totals, nb)
		var hour Totals
		st.hist.each(func(p *Point) {
			if !p.At.After(start) || p.At.After(now) {
				return
			}
			hour.add(p)
			i := min(int(p.At.Sub(start)/BinWidth), nb-1)
			bins[i].add(p)
		})
		v.Hour = rates(hour)
		if hour.Secs > 0 {
			fleetHour.merge(hour)
			qpsHour += float64(hour.Queries()) / hour.Secs
			anyHour = true
		}
		if p := st.hist.last(); p != nil && now.Sub(p.At) <= fresh && st.online {
			var t Totals
			t.add(p)
			r := rates(t)
			v.Now = &r
			fleetNow.merge(t)
			qpsNow += float64(t.Queries()) / t.Secs
			anyNow = true
		}
		for i, b := range bins {
			if b.Secs <= 0 {
				continue
			}
			q := float64(b.Queries()) / b.Secs
			v.QPS[i] = f64(q)
			fleetBins[i].merge(b)
			fleetQPS[i] += q
			fleetBlocked[i] += float64(b.Blocked()) / b.Secs
			fleetHas[i] = true
		}
		if st.metrics.State == "ok" {
			d.Fleet.Reading++
		}
		d.Nodes = append(d.Nodes, v)
	}
	if d.Nodes == nil {
		d.Nodes = []NodeView{}
	}
	d.Fleet.Nodes = len(d.Nodes)
	d.Fleet.Hour = rates(fleetHour)
	d.Fleet.Hour.QPS, d.Fleet.Hour.BusyShare = nil, nil
	if anyHour {
		d.Fleet.Hour.QPS = f64(qpsHour)
	}
	d.Fleet.Now = rates(fleetNow)
	d.Fleet.Now.QPS, d.Fleet.Now.BusyShare = nil, nil
	if anyNow {
		d.Fleet.Now.QPS = f64(qpsNow)
	}
	f := &d.Fleet
	f.QPS, f.Blocked, f.P95, f.UpP95 = make(Series, nb), make(Series, nb), make(Series, nb), make(Series, nb)
	f.UpFail, f.HitRate, f.ServFail = make(Series, nb), make(Series, nb), make(Series, nb)
	for i := range nb {
		if !fleetHas[i] {
			continue
		}
		b := fleetBins[i]
		r := rates(b)
		f.QPS[i], f.Blocked[i] = f64(fleetQPS[i]), f64(fleetBlocked[i])
		f.P95[i], f.UpP95[i], f.HitRate[i] = r.P95, r.UpP95, r.CacheHitRate
		f.UpFail[i], f.ServFail[i] = f64(float64(b.UpFail)), f64(float64(r.ServFail))
	}
	return d
}

// ---- the query log ----

// Log reads the buffer: the newest f.Limit entries that match, newest first by time.
func (s *Store) Log(f Filter) LogView {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	f.Limit = min(f.Limit, 1000)
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Run != "" && f.Run != s.run {
		f.After = 0 // the IDs of another run: read from the start
	}
	v := LogView{Run: s.run, Held: len(s.log.buf), Cap: LogCap, Last: s.nextID, Entries: []Entry{}}
	var all []*Entry
	s.log.each(func(e *Entry) {
		if v.Oldest == nil || e.At.Before(*v.Oldest) {
			t := e.At
			v.Oldest = &t
		}
		if v.Newest == nil || e.At.After(*v.Newest) {
			t := e.At
			v.Newest = &t
		}
		if f.match(e) {
			all = append(all, e)
		}
	})
	v.Matched = len(all)
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].At.Equal(all[j].At) {
			return all[i].At.After(all[j].At)
		}
		return all[i].ID > all[j].ID
	})
	for _, e := range all[:min(len(all), f.Limit)] {
		v.Entries = append(v.Entries, *e)
	}
	v.Nodes = s.logNodes()
	return v
}

func (s *Store) logNodes() []LogNode {
	out := []LogNode{}
	for k, st := range s.nodes {
		out = append(out, LogNode{Key: k, Name: st.name, Addr: st.addr, QLState: st.ql})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// Top counts the names in the buffer (node: one node's only), over the span it holds.
func (s *Store) Top(node string) Top {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := Top{Queried: []TopName{}, Blocked: []TopName{}}
	all, blocked := map[string]int{}, map[string]int{}
	s.log.each(func(e *Entry) {
		if node != "" && e.Node != node {
			return
		}
		t.Entries++
		if t.Oldest == nil || e.At.Before(*t.Oldest) {
			x := e.At
			t.Oldest = &x
		}
		if t.Newest == nil || e.At.After(*t.Newest) {
			x := e.At
			t.Newest = &x
		}
		name := strings.ToLower(e.QName)
		all[name]++
		if Blocks(e.Result) {
			blocked[name]++
			t.Blocks++
		}
	})
	t.Queried, t.Blocked = top(all), top(blocked)
	return t
}
