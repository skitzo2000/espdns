// Package nodes keeps the list of espDNS nodes: found over mDNS (_espdns._tcp), listed by
// address in the settings, or looked up at an address typed (Lookup: a node mDNS doesn't
// reach, on another network), and polled over HTTP (/status) to show their state. Read-only:
// the poller only GETs /status, which carries the node's health (the same state and reasons
// as /health, which came in the same firmware) and the state of every stored input, so
// /health isn't asked as well.
package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/zeroconf/v2"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

const (
	service      = "_espdns._tcp"
	browseEvery  = 30 * time.Second
	browseWindow = 5 * time.Second
	pollEvery    = 10 * time.Second
	pollTimeout  = 3 * time.Second
	offlineAfter = 3 * pollEvery
	// pruneAfter: a node found over mDNS (not in settings.json) is dropped from the list once
	// it has neither answered /status nor been seen over mDNS for this long (docs/design.md,
	// Controller). A node in settings.json stays listed (offline) until it is taken out.
	pruneAfter = 10 * time.Minute
	// maxStatus caps a /status body: a node's is a few KB, and anything answering on a
	// node's address could send more.
	maxStatus = 256 << 10
	// maxLookedUp caps the nodes kept from Lookup (not in settings.json, not seen over
	// mDNS): one more drops the one looked up longest ago.
	maxLookedUp = 8
	// maxFound caps the nodes listed from mDNS alone (not in settings.json): mDNS answers
	// aren't authenticated, and any device on the LAN could announce any number of them,
	// each one polled. A fleet is a handful of nodes; past the cap a new one is ignored
	// (logged) until one is pruned or listed in settings.json. With maxStatus, it bounds
	// what the registry holds (64 × 256 KB).
	maxFound = 64
)

// The sources of a node in the list.
const (
	SourceSettings = "settings" // listed in settings.json
	SourceMDNS     = "mdns"     // found over mDNS
	SourceLookup   = "lookup"   // looked up at an address typed (Lookup)
)

// Node is what the controller knows about one node.
type Node struct {
	ID       string `json:"id"`       // chip MAC (node_id in /status): what signed releases bind to
	Addr     string `json:"addr"`     // IPv4 address it is polled on
	Hostname string `json:"hostname"` // mDNS name, e.g. espdns-cde868.local
	// MAC is the MAC of the interface the node uses (/status net.mac, release.MAC): what a
	// DHCP reservation, or setting a static address, goes by. Kept while the node is offline,
	// as Status is; "" until it reports one.
	MAC      string    `json:"mac,omitempty"`
	Source   string    `json:"source"` // SourceSettings, SourceMDNS or SourceLookup
	Online   bool      `json:"online"`
	LastSeen time.Time `json:"last_seen"`
	Error    string    `json:"error,omitempty"` // why the last poll failed (cleared by the next good one)
	Polled   time.Time `json:"polled"`          // the last poll, answered or not
	// QPS is the queries a second over the last two answered polls (from /status
	// queries.total); nil until there are two, after a reboot (the count started over), or
	// on firmware without the count.
	QPS *float64 `json:"qps,omitempty"`
	// The node's last /status, as it sent it: kept while the node is offline (LastSeen says
	// how old it is), so the page can show what it last knew.
	Status map[string]any `json:"status,omitempty"`

	total   float64   // queries.total at LastSeen, for QPS; -1: none
	totalAt time.Time // when it was read
	uptime  float64   // uptime_s at LastSeen: a smaller one means it rebooted; -1: none
	found   time.Time // last seen over mDNS, or looked up
}

// foundOnly says whether a node of this source is listed only because it was found (over
// mDNS, or by Lookup), not because settings.json lists it: such a node is pruned when
// unseen, and moves with its ID once its own /status at the new address gives that ID.
func foundOnly(source string) bool { return source == SourceMDNS || source == SourceLookup }

// Registry holds the nodes and keeps them up to date.
type Registry struct {
	mu     sync.Mutex
	byAddr map[string]*Node
	static []string
	client *http.Client
	now    func() time.Time
	polled []func([]Node)
	full   bool                  // maxFound reached (logged once until below it again)
	browse func(context.Context) // one mDNS browse (r.browseMDNS; a test's stand-in)
	wait   time.Duration         // how long Lookup waits for /status (pollTimeout; a test's shorter)
}

// New returns a registry that also polls these addresses, whether or not mDNS finds them.
func New(static []string) *Registry {
	r := &Registry{byAddr: map[string]*Node{}, static: static, client: &http.Client{Timeout: pollTimeout}, now: time.Now,
		wait: pollTimeout}
	r.browse = r.browseMDNS
	for _, a := range static {
		r.byAddr[a] = &Node{Addr: a, Source: SourceSettings, total: -1, uptime: -1}
	}
	return r
}

// SetClient sets the HTTP client /status is read with (a test's fake network). Before Run.
func (r *Registry) SetClient(c *http.Client) { r.client = c }

// SetListed replaces the addresses polled whether or not mDNS finds them (settings.json's
// nodes, read again): a new one is polled from the next poll on, one no longer listed is
// dropped unless mDNS found it too, and a node found over mDNS that is listed now counts as
// listed.
func (r *Registry) SetListed(addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.static {
		if n := r.byAddr[a]; n != nil && n.Source == SourceSettings && !slices.Contains(addrs, a) {
			delete(r.byAddr, a)
		}
	}
	for _, a := range addrs {
		switch n := r.byAddr[a]; {
		case n == nil:
			r.byAddr[a] = &Node{Addr: a, Source: SourceSettings, total: -1, uptime: -1}
		case foundOnly(n.Source):
			n.Source = SourceSettings
		}
	}
	r.static = slices.Clone(addrs)
}

// OnPoll has f called with the list after each poll (in the poller's goroutine: f must not
// block). Before Run.
func (r *Registry) OnPoll(f func([]Node)) { r.polled = append(r.polled, f) }

// Run polls until ctx ends, and with mdns browses mDNS for nodes besides the listed ones;
// without it only the listed addresses are polled and nothing else is sent anywhere.
func (r *Registry) Run(ctx context.Context, mdns bool) {
	if mdns {
		go r.browseLoop(ctx)
	}
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		r.pollAll(ctx)
		if len(r.polled) > 0 {
			list := r.List()
			for _, f := range r.polled {
				f(list)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// List returns the nodes, sorted by address.
func (r *Registry) List() []Node {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Node, 0, len(r.byAddr))
	for _, n := range r.byAddr {
		out = append(out, r.view(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// view is n as List shows it: a copy, online or not now. Call with r.mu held.
func (r *Registry) view(n *Node) Node {
	c := *n
	c.Online = !n.LastSeen.IsZero() && r.now().Sub(n.LastSeen) < offlineAfter
	return c
}

// ErrNoAnswer and ErrNotNode are why Lookup found no node: nothing answered HTTP at the
// address in time, or what answered isn't an espDNS node's /status.
var (
	ErrNoAnswer = errors.New("nothing answers there")
	ErrNotNode  = errors.New("no espDNS node answers there")
)

// Lookup reads /status at addr, and only there, within pollTimeout: the node a person
// typed the address of (one mDNS doesn't reach: on another network, or with mDNS
// filtered). A node that answers is listed from then on (SourceLookup, unless it is
// listed already) and polled as the others, until it is pruned as one found over mDNS is
// (gone for pruneAfter); one more than maxLookedUp drops the one looked up longest ago. A
// node found before at another address (not in settings.json) moves to this one: the ID
// comes from the node's own /status at the address typed, not from an unauthenticated mDNS
// answer. Nothing is listed for an address where no espDNS node answers. It returns the
// node as List would.
func (r *Registry) Lookup(ctx context.Context, addr string) (Node, error) {
	ctx, cancel := context.WithTimeout(ctx, r.wait)
	defer cancel()
	st, err := r.status(ctx, addr)
	var ue *url.Error
	switch {
	case errors.As(err, &ue):
		err = fmt.Errorf("%w: %v", ErrNoAnswer, ue.Err)
	case err != nil:
		err = fmt.Errorf("%w: %v", ErrNotNode, err)
	default:
		if id, _ := st["node_id"].(string); id == "" {
			err = fmt.Errorf("%w: its /status names no node_id", ErrNotNode)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.byAddr[addr]
	if err != nil {
		if n != nil {
			r.record(n, nil, err)
		}
		return Node{}, err
	}
	if n == nil {
		id, _ := st["node_id"].(string)
		// A node keeps its ID when its address changes: one found before (over mDNS, or
		// looked up) at its old address moves, rather than being listed twice with the same
		// ID.
		if old := r.byID(id); old != nil && foundOnly(old.Source) {
			log.Printf("looked up %s: node %s, moved from %s", addr, id, old.Addr)
			delete(r.byAddr, old.Addr)
			n = old
			n.Addr = addr
		} else {
			r.makeRoomForLookup()
			n = &Node{Addr: addr, Source: SourceLookup, total: -1, uptime: -1}
			log.Printf("looked up %s: node %s", addr, id)
		}
		r.byAddr[addr] = n
	}
	if foundOnly(n.Source) {
		n.found = r.now()
	}
	r.record(n, st, nil)
	return r.view(n), nil
}

// makeRoomForLookup drops the nodes looked up longest ago until there is room for one
// more under maxLookedUp. Call with r.mu held.
func (r *Registry) makeRoomForLookup() {
	for {
		var oldest *Node
		count := 0
		for _, n := range r.byAddr {
			if n.Source != SourceLookup {
				continue
			}
			count++
			if oldest == nil || n.found.Before(oldest.found) {
				oldest = n
			}
		}
		if count < maxLookedUp {
			return
		}
		log.Printf("%s (%s): dropped from the list, for a node looked up since", oldest.Addr, oldest.ID)
		delete(r.byAddr, oldest.Addr)
	}
}

func (r *Registry) browseLoop(ctx context.Context) {
	for {
		r.browse(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(browseEvery):
		}
	}
}

func (r *Registry) browseMDNS(ctx context.Context) {
	entries := make(chan *zeroconf.ServiceEntry)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			if a, ok := nodeAddr(e.AddrIPv4); ok {
				r.seen(a, e.Instance, e.HostName, e.Text)
			}
		}
	}()
	bctx, cancel := context.WithTimeout(ctx, browseWindow)
	defer cancel()
	if err := zeroconf.Browse(bctx, service, "local.", entries); err != nil {
		log.Printf("mdns browse: %v", err)
	}
	<-done
}

// nodeAddr is the first of an mDNS answer's IPv4 addresses a node can have: never
// loopback, link-local, multicast, unspecified, "this network" (0/8) or broadcast (an
// answer naming one would have the controller poll itself or something no node is).
func nodeAddr(ips []net.IP) (string, bool) {
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() ||
			thisNet.Contains(a) || a == broadcast {
			continue
		}
		return a.String(), true
	}
	return "", false
}

var (
	thisNet   = netip.MustParsePrefix("0.0.0.0/8")
	broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// seen takes one mDNS answer: the node at addr (instance, hostname, its TXT entries), added
// if new and marked as seen now. An answer is not authenticated, so it never moves a node
// nor renames one: a node known at addr under another ID keeps it (the answer is ignored),
// and a new address announced under a known node's ID is listed on its own, without that
// ID, until its own /status gives one (record, which moves a node found only once its old
// address has stopped answering). At most maxFound nodes are listed from mDNS alone.
func (r *Registry) seen(addr, instance, hostname string, text []string) {
	id := txt(text, "node")
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.byAddr[addr]
	if ok && id != "" && n.ID != "" && !strings.EqualFold(n.ID, id) {
		log.Printf("mdns: %s announces %s as %s, known there as %s: ignored", instance, addr, id, n.ID)
		return
	}
	if !ok {
		if r.found() >= maxFound {
			if !r.full { // once, until below the cap again
				log.Printf("mdns: %d nodes found over mDNS alone, the most listed: %s at %s ignored "+
					"(list a node in settings.json to keep it)", maxFound, instance, addr)
				r.full = true
			}
			return
		}
		r.full = false
		n = &Node{Addr: addr, Source: SourceMDNS, total: -1, uptime: -1}
		r.byAddr[addr] = n
	}
	// An ID another node has is never taken from an answer, for a new address or one
	// already listed without an ID (a node listed apart, announced again): only its own
	// /status gives it (record).
	if old := r.byID(id); id != "" && n.ID == "" && old != nil && old != n {
		if !ok {
			log.Printf("mdns: %s announces %s at %s, known at %s: listed apart until its /status says who it is",
				instance, id, addr, old.Addr)
		}
		id = ""
	} else if !ok {
		log.Printf("found %s at %s (%s)", instance, addr, strings.Join(text, " "))
	}
	if n.Source == SourceLookup {
		n.Source = SourceMDNS // mDNS finds it too now
	}
	if id != "" {
		n.ID = id
	}
	n.Hostname = strings.TrimSuffix(hostname, ".")
	n.found = r.now()
}

// found is how many nodes are listed from mDNS alone. Call with r.mu held.
func (r *Registry) found() int {
	c := 0
	for _, n := range r.byAddr {
		if n.Source == SourceMDNS {
			c++
		}
	}
	return c
}

// moved drops the node found only (over mDNS, or by Lookup) that had n's ID at another
// address, now that n's /status gives that ID, once it has stopped answering there: a node
// renumbered (DHCP, another network) is listed once. One still answering stays (two answer
// as one node: both listed, for you to see); a node in settings.json is never dropped. Call
// with r.mu held.
func (r *Registry) moved(n *Node) {
	if n.ID == "" {
		return
	}
	for a, o := range r.byAddr {
		if o == n || !foundOnly(o.Source) || !strings.EqualFold(o.ID, n.ID) {
			continue
		}
		if !o.LastSeen.IsZero() && r.now().Sub(o.LastSeen) < offlineAfter {
			continue
		}
		log.Printf("%s moved from %s to %s", n.ID, a, n.Addr)
		delete(r.byAddr, a)
	}
}

// prune drops the nodes found over mDNS or by Lookup only (not in settings.json) that
// neither answered a poll nor were seen over mDNS (or looked up) for pruneAfter: a node
// retired, moved off this network or renumbered isn't listed for ever. Call with r.mu held.
func (r *Registry) prune() {
	now := r.now()
	for a, n := range r.byAddr {
		if !foundOnly(n.Source) {
			continue
		}
		last := n.found
		if n.LastSeen.After(last) {
			last = n.LastSeen
		}
		if now.Sub(last) >= pruneAfter {
			log.Printf("%s (%s): not seen for %v, dropped from the list", a, n.ID, pruneAfter)
			delete(r.byAddr, a)
		}
	}
}

// byID returns the node with this ID, if any. Call with r.mu held.
func (r *Registry) byID(id string) *Node {
	if id == "" {
		return nil
	}
	for _, n := range r.byAddr {
		if strings.EqualFold(n.ID, id) {
			return n
		}
	}
	return nil
}

// txt returns the value of key in an mDNS TXT record list ("key=value" entries).
func txt(entries []string, key string) string {
	for _, e := range entries {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func (r *Registry) pollAll(ctx context.Context) {
	r.mu.Lock()
	addrs := make([]string, 0, len(r.byAddr))
	for a := range r.byAddr {
		addrs = append(addrs, a)
	}
	r.mu.Unlock()
	var wg sync.WaitGroup
	for _, a := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			st, err := r.status(ctx, addr)
			r.mu.Lock()
			defer r.mu.Unlock()
			if n := r.byAddr[addr]; n != nil { // nil: dropped as moved, or pruned, while this poll ran
				r.record(n, st, err)
			}
		}(a)
	}
	wg.Wait()
	r.mu.Lock()
	r.prune()
	r.mu.Unlock()
}

// record takes one read of n's /status (st, or why it failed): when, the error or the
// status, the queries a second, its ID, host name and MAC. Call with r.mu held.
func (r *Registry) record(n *Node, st map[string]any, err error) {
	now := r.now()
	n.Polled = now
	if err != nil {
		n.Error = err.Error()
		return
	}
	n.Error = ""
	n.Status = st
	n.LastSeen = now
	n.QPS = nil
	total, ok := queriesTotal(st)
	up, upOK := st["uptime_s"].(float64)
	rebooted := upOK && n.uptime >= 0 && up < n.uptime
	n.uptime = -1
	if upOK {
		n.uptime = up
	}
	if ok && !rebooted && n.total >= 0 && total >= n.total && now.After(n.totalAt) {
		q := (total - n.total) / now.Sub(n.totalAt).Seconds()
		n.QPS = &q
	}
	n.total, n.totalAt = -1, now
	if ok {
		n.total = total
	}
	if id, ok := st["node_id"].(string); ok {
		n.ID = id
		r.moved(n)
	}
	net, _ := st["net"].(map[string]any)
	if n.Hostname == "" {
		n.Hostname, _ = net["hostname"].(string)
	}
	mac, _ := net["mac"].(string)
	n.MAC = release.MAC(mac)
}

// queriesTotal is /status queries.total, the queries the node has taken since boot.
func queriesTotal(st map[string]any) (float64, bool) {
	q, _ := st["queries"].(map[string]any)
	t, ok := q["total"].(float64)
	return t, ok
}

func (r *Registry) status(ctx context.Context, addr string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/status", nil)
	if err != nil {
		return nil, err
	}
	// A node answers /status itself: a redirect isn't followed (it would have the controller
	// ask another host, one Lookup's caller never typed), it is an answer that isn't a node's.
	c := *r.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/status: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatus+1))
	if err != nil {
		return nil, fmt.Errorf("/status: %w", err)
	}
	if len(body) > maxStatus {
		return nil, fmt.Errorf("/status: over %d KB", maxStatus>>10)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("/status: %w", err)
	}
	if st == nil {
		return nil, fmt.Errorf("/status: not a JSON object")
	}
	return st, nil
}

// Find browses mDNS for the node with this ID (its chip MAC, the "node" TXT entry) for up
// to window, and returns its IPv4 address. Pure Go: it works in the static binary, which
// can't resolve .local names through the system resolver.
func Find(ctx context.Context, id string, window time.Duration) (string, error) {
	entries := make(chan *zeroconf.ServiceEntry)
	bctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	found := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			if a, ok := nodeAddr(e.AddrIPv4); ok && strings.EqualFold(txt(e.Text, "node"), id) {
				select {
				case found <- a:
				default:
				}
				cancel()
			}
		}
	}()
	if err := zeroconf.Browse(bctx, service, "local.", entries); err != nil {
		return "", err
	}
	<-done   // an entry taken just as the window closed is in found too
	select { // the browser sends the address before it cancels
	case a := <-found:
		return a, nil
	default:
		return "", fmt.Errorf("node %s not found over mDNS", id)
	}
}

// Advert is one node as it advertises itself over mDNS (firmware/main/net.c).
type Advert struct {
	Addr     string `json:"addr"`
	Hostname string `json:"hostname"`
	ID       string `json:"id"`
	Board    string `json:"board"`
	Image    string `json:"image"`
	Version  string `json:"version"`
	Net      string `json:"net"`
	Adopted  bool   `json:"adopted"` // the node runs on a pushed config ("adopted=1")
}

// Browse lists the nodes that answer an mDNS browse for _espdns._tcp within window, sorted
// by address. Pure Go, as Find.
func Browse(ctx context.Context, window time.Duration) ([]Advert, error) {
	entries := make(chan *zeroconf.ServiceEntry)
	bctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	byAddr := map[string]Advert{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			addr, ok := nodeAddr(e.AddrIPv4)
			if _, known := byAddr[addr]; !ok || (!known && len(byAddr) >= maxFound) {
				continue
			}
			a := Advert{Addr: addr, Hostname: strings.TrimSuffix(e.HostName, "."),
				ID: txt(e.Text, "node"), Board: txt(e.Text, "board"), Image: txt(e.Text, "image"),
				Version: txt(e.Text, "version"), Net: txt(e.Text, "net"), Adopted: txt(e.Text, "adopted") == "1"}
			byAddr[a.Addr] = a
		}
	}()
	if err := zeroconf.Browse(bctx, service, "local.", entries); err != nil {
		return nil, err
	}
	<-done
	out := make([]Advert, 0, len(byAddr))
	for _, a := range byAddr {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, nil
}
