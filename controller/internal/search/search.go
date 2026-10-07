// Package search is the GUI's one search (docs/plan.md, The GUI redesign: "one search box
// answers 'what's happening with X?' for a site, a device or a node"): one query, matched
// against what the controller already holds, each result typed and saying where it lives
// in the GUI.
//
// It searches, in this order, and nothing else:
//
//	nodes      every node the controller knows: its name, host names, address, ID and board
//	zones      every zone the fleet answers for (internal/inventory), and the zone a name is in
//	records    the hosted zones' records, as the pending changes make them: owner and data
//	devices    the query log's clients, by address or by a record's name for their address
//	sites      the names in the query log
//	check      a site name typed whole: Blocking's "check a site" for it
//	rules      the allowed and blocked sites (the overrides), as the pending changes make them
//	lists      the blocklists (their definitions, as the pending changes make them): name and sources
//	changes    the pending changes: summary, file, firmware and nodes
//
// Each query's work is bounded: the query is 253 bytes at most; every source is the
// controller's own (files in the data directory, each capped by its store, and the query
// log's buffer of observe.LogCap entries) and is read once; a deadline (Budget) is checked
// between the sources and inside the longer loops, and a search that runs out of time says
// so (Partial) with what it found; at most PerType results of a type and Max in all are
// returned (More says some were left out). A search sends nothing over the network: no node,
// primary or list URL is asked.
package search

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/blocking"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/changes"
	"github.com/skitzo2000/espdns/controller/internal/inventory"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/observe"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

const (
	// MaxQuery is the longest query taken: a domain name's longest.
	MaxQuery = 253
	// PerType is the most results of one type; Max the most in all.
	PerType = 10
	Max     = 50
	// Budget is how long one search may take.
	Budget = 2 * time.Second
	// checkEvery is how many items a long loop goes through between looks at the deadline.
	checkEvery = 1024
)

// The types of result.
const (
	TypeNode   = "node"
	TypeZone   = "zone"
	TypeRecord = "record"
	TypeDevice = "device"
	TypeSite   = "site"
	TypeCheck  = "check"
	TypeRule   = "rule"
	TypeList   = "list"
	TypeChange = "change"
)

// typeOrder orders results of the same rank.
var typeOrder = []string{TypeNode, TypeZone, TypeRecord, TypeDevice, TypeSite, TypeCheck, TypeRule, TypeList, TypeChange}

// The GUI's pages (docs/plan.md, The prototype: Nodes, Zones, Blocking, Query log, and the
// pending changes in the header).
const (
	PageNodes    = "nodes"
	PageZones    = "zones"
	PageBlocking = "blocking"
	PageQueryLog = "query-log"
	PageChanges  = "changes"
)

// Result is one thing found.
type Result struct {
	Type  string `json:"type"`
	Title string `json:"title"` // what it is called: dns2, home.example, printer.home.example
	Text  string `json:"text"`  // what it is, in words
	// Where it lives in the GUI: its page, its key there (a node's ID or address, a zone's
	// name, a record's owner, a client's address, a site's or a list's name, a change's ID)
	// and the GUI's address for it (a node's or a zone's own page, #node-<key> and
	// #zone-<name> as the prototype names them; else its page with a filter or a choice).
	Page string `json:"page"`
	Key  string `json:"key"`
	Link string `json:"link"`
	// Match is what the query matched: name, address, id, board, within (a name inside it),
	// data (a record's), client, source (a list's), covers (a rule for the name's parent),
	// summary, file, typed (the query itself).
	Match string `json:"match"`
	// State is a node's health ("offline" when it doesn't answer), a zone's state, a rule's
	// allow or block.
	State string `json:"state,omitempty"`
	// Zone is the zone a record is in.
	Zone string `json:"zone,omitempty"`
	// Pending: it is so in the pending changes, not applied yet.
	Pending bool `json:"pending,omitempty"`
	// A device's or a site's queries in the query log the controller holds: how many, how
	// many blocked, the last.
	Queries int        `json:"queries,omitempty"`
	Blocked int        `json:"blocked,omitempty"`
	Last    *time.Time `json:"last,omitempty"`

	rank int // 0 exact, 1 a prefix (or a name inside it), 2 a part
}

// Answer is a search's results.
type Answer struct {
	Query   string   `json:"query"`
	Results []Result `json:"results"` // the best first: exact, then prefix, then part; by type
	// Matched is how many of each type matched, before the caps.
	Matched map[string]int `json:"matched"`
	More    bool           `json:"more"`    // some results were left out (PerType, Max)
	Partial bool           `json:"partial"` // the time ran out: not every place was searched
	// Searched are the places searched, in order; Problems what could not be read, and why.
	Searched []string `json:"searched"`
	Problems []string `json:"problems"`
}

// Input is what a search reads: the controller's own state, nothing remote.
type Input struct {
	DataDir string
	Changes *changes.Store // the pending changes (nil: none, files as they are)
	Log     *observe.Store // the query log (nil: none)
	// Nodes are every node the controller knows (Source "settings": listed in settings.json).
	Nodes []nodes.Node
	// Inventory is the fleet's zones (internal/inventory).
	Inventory inventory.Inventory
}

// CheckQuery makes a query typed in the search's: trimmed, lowercase, without a name's
// root dot. It refuses an empty one, one over MaxQuery bytes and one with control
// characters.
func CheckQuery(raw string) (string, error) {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	switch {
	case q == "":
		return "", errors.New("nothing to search for")
	case len(q) > MaxQuery:
		return "", fmt.Errorf("a search is %d characters at most", MaxQuery)
	case strings.IndexFunc(q, unicode.IsControl) >= 0:
		return "", errors.New("a search can't hold control characters")
	}
	return q, nil
}

// rank is how s matches q (lowercase): 0 exact, 1 a prefix, 2 a part, -1 none.
func rank(s, q string) int {
	s = strings.ToLower(s)
	switch {
	case s == "":
		return -1
	case s == q:
		return 0
	case strings.HasPrefix(s, q):
		return 1
	case strings.Contains(s, q):
		return 2
	}
	return -1
}

// best is the best rank of q in any of fields, and the field's name.
func best(q string, fields ...[2]string) (int, string) {
	r, what := -1, ""
	for _, f := range fields {
		if x := rank(f[1], q); x >= 0 && (r < 0 || x < r) {
			r, what = x, f[0]
		}
	}
	return r, what
}

// link is the GUI's address of a page with a filter or a choice on it.
func link(page, param, value string) string {
	return "#" + page + "?" + param + "=" + url.QueryEscape(value)
}

// item is the GUI's address of a node's or a zone's own page, as the prototype names them
// (#node-<key>, #zone-<name>).
func item(what, key string) string { return "#" + what + "-" + url.PathEscape(key) }

// search is one search in progress.
type search struct {
	ctx context.Context
	in  Input
	q   string
	// out are the best PerType results of each type so far (finish orders and caps them):
	// a query that matches much keeps no more than that, whatever it matched.
	out map[string][]Result
	ans *Answer
	// hosts are the hosted records' addresses (A, AAAA) and the names that have them.
	hosts map[string][]string
	// devices are the addresses of the records the query matched, with their rank.
	devices map[string]int
}

// Run searches for q (CheckQuery's) in what in holds, until ctx ends or Budget is spent.
func Run(ctx context.Context, in Input, q string) Answer {
	ctx, cancel := context.WithTimeout(ctx, Budget)
	defer cancel()
	ans := Answer{Query: q, Results: []Result{}, Matched: map[string]int{}, Searched: []string{}, Problems: []string{}}
	s := &search{ctx: ctx, in: in, q: q, ans: &ans, out: map[string][]Result{}, hosts: map[string][]string{}, devices: map[string]int{}}
	for _, p := range []struct {
		name string
		run  func() error
	}{
		{"nodes", s.nodes},
		{"zones", s.zones},
		{"records", s.records},
		{"query log", s.queryLog},
		{"check", s.check},
		{"rules", s.rules},
		{"lists", s.lists},
		{"changes", s.changes},
	} {
		if ctx.Err() != nil {
			ans.Partial = true
			break
		}
		if err := p.run(); err != nil {
			if ctx.Err() != nil {
				ans.Partial = true
				break
			}
			ans.Problems = append(ans.Problems, p.name+": "+err.Error())
		}
		ans.Searched = append(ans.Searched, p.name)
	}
	s.finish()
	return ans
}

// add takes a result that matched (rank 0 to 2), kept if it is among its type's best
// PerType so far.
func (s *search) add(r Result) {
	s.ans.Matched[r.Type]++
	l := s.out[r.Type]
	i, _ := slices.BinarySearchFunc(l, r, order)
	if i >= PerType {
		s.ans.More = true
		return
	}
	l = slices.Insert(l, i, r)
	if len(l) > PerType {
		l = l[:PerType]
		s.ans.More = true
	}
	s.out[r.Type] = l
}

// order is the results' order: the best rank first, then by type, then by title.
func order(a, b Result) int {
	if a.rank != b.rank {
		return a.rank - b.rank
	}
	if c := slices.Index(typeOrder, a.Type) - slices.Index(typeOrder, b.Type); c != 0 {
		return c
	}
	return strings.Compare(a.Title, b.Title)
}

// late says whether the deadline passed, looked at every checkEvery items.
func (s *search) late(i int) bool { return i%checkEvery == checkEvery-1 && s.ctx.Err() != nil }

// finish orders the results and applies the caps.
func (s *search) finish() {
	var all []Result
	for _, l := range s.out {
		all = append(all, l...)
	}
	slices.SortStableFunc(all, order)
	if len(all) > Max {
		all = all[:Max]
		s.ans.More = true
	}
	s.ans.Results = append(s.ans.Results, all...)
}

// ---- nodes ----

func (s *search) nodes() error {
	for _, n := range s.in.Nodes {
		var st release.NodeStatus
		if n.Status != nil {
			if b, err := json.Marshal(n.Status); err == nil {
				json.Unmarshal(b, &st)
			}
		}
		name := ""
		if st.Config != nil {
			name = st.Config.Name
		}
		mdns := strings.TrimSuffix(n.Hostname, ".local")
		r, what := best(s.q, [2]string{"name", name}, [2]string{"name", st.Net.Hostname}, [2]string{"name", mdns},
			[2]string{"name", n.Hostname}, [2]string{"address", n.Addr}, [2]string{"address", st.IP},
			[2]string{"id", n.ID}, [2]string{"id", st.Net.MAC}, [2]string{"board", st.Board})
		if r < 0 {
			continue
		}
		title := firstOf(name, st.Net.Hostname, mdns, n.Addr)
		state := "offline"
		if n.Online {
			state = "answering"
			if st.Health != nil && st.Health.State != "" {
				state = st.Health.State
			}
		}
		text := "a node at " + n.Addr
		if st.Board != "" {
			text = st.Board + " at " + n.Addr
		}
		text += ", " + state
		if n.Source != "settings" {
			text += "; found on the network, not added"
		}
		key := observe.Key(n)
		s.add(Result{Type: TypeNode, Title: title, Text: text, Page: PageNodes, Key: key, Link: item("node", key),
			Match: what, State: state, rank: r})
	}
	return nil
}

func firstOf(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---- zones ----

func (s *search) zones() error {
	for _, z := range s.in.Inventory.Zones {
		r, what := rank(z.Name, s.q), "name"
		if r < 0 && strings.HasSuffix(s.q, "."+strings.ToLower(z.Name)) {
			r, what = 1, "within"
		}
		if r < 0 {
			continue
		}
		var kind string
		switch z.Kind {
		case inventory.KindHosted:
			kind = "hosted here"
		case inventory.KindSecondary:
			kind = "copied from your primary"
			if z.Primary != "" {
				kind = "copied from the primary at " + z.Primary
			}
		case inventory.KindForward:
			kind = "forwarded"
			if len(z.Forwarders) > 0 {
				kind = "forwarded to " + strings.Join(z.Forwarders, ", ")
			}
		}
		s.add(Result{Type: TypeZone, Title: z.Name, Text: kind + ": " + z.Text, Page: PageZones, Key: z.Name,
			Link: item("zone", z.Name), Match: what, State: z.State, rank: r})
	}
	return nil
}

// ---- records ----

// view is a file as the pending changes make it (as it is without a store).
func (s *search) view(k changes.Kind, name string) (changes.View, error) {
	if s.in.Changes == nil {
		return changes.Current(s.in.DataDir, k, name)
	}
	return s.in.Changes.Effective(k, name)
}

// zoneFiles are the hosted zones' files, and those pending changes add.
func (s *search) zoneFiles() ([]string, error) {
	names, err := zonefiles.Store(s.in.DataDir).Names()
	if err != nil {
		return nil, err
	}
	if s.in.Changes != nil {
		cs, err := s.in.Changes.List()
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			if c.Kind == changes.Zone && !slices.Contains(names, c.Name) {
				names = append(names, c.Name)
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

func (s *search) records() error {
	names, err := s.zoneFiles()
	if err != nil {
		return err
	}
	var problems []string
	i := 0
	for _, name := range names {
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		v, err := s.view(changes.Zone, name)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !v.Exists {
			continue
		}
		z, err := zonefiles.Parse(name, v.Text)
		if err != nil {
			continue // the zone's own page says why; the inventory names it an error
		}
		zone := z.Name()
		applied := s.appliedRecords(name, v)
		for _, rec := range z.Records {
			if i++; s.late(i) {
				return s.ctx.Err()
			}
			if rec.Type == dns.TypeSOA {
				continue
			}
			rr, err := text(rec)
			if err != nil {
				continue
			}
			owner := strings.TrimSuffix(rr.Header().Name, ".")
			data := strings.TrimSuffix(strings.TrimPrefix(rr.String(), rr.Header().String()), ".")
			switch a := rr.(type) {
			case *dns.A:
				s.hosts[a.A.String()] = addOnce(s.hosts[a.A.String()], owner)
			case *dns.AAAA:
				s.hosts[a.AAAA.String()] = addOnce(s.hosts[a.AAAA.String()], owner)
			}
			r, what := best(s.q, [2]string{"name", owner}, [2]string{"data", data})
			if r < 0 {
				continue
			}
			typ := dns.TypeToString[rec.Type]
			if addr := address(rr); addr != "" {
				if d, ok := s.devices[addr]; !ok || r < d {
					s.devices[addr] = r
				}
			}
			s.add(Result{Type: TypeRecord, Title: owner, Text: typ + " " + data + ", in " + zone, Page: PageZones, Key: owner,
				Link: item("zone", zone), Match: what, Zone: zone, Pending: applied != nil && !applied[strings.ToLower(rr.String())], rank: r})
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// appliedRecords are the records (lowercase, as dns.RR's String) of the zone file as it is
// now, when pending changes make v (nil when none do): a record not in it is pending.
func (s *search) appliedRecords(name string, v changes.View) map[string]bool {
	if len(v.Pending) == 0 {
		return nil
	}
	applied := map[string]bool{}
	cur, err := changes.Current(s.in.DataDir, changes.Zone, name)
	if err != nil || !cur.Exists {
		return applied
	}
	z, err := zonefiles.Parse(name, cur.Text)
	if err != nil {
		return applied
	}
	for _, rec := range z.Records {
		if rr, err := text(rec); err == nil {
			applied[strings.ToLower(rr.String())] = true
		}
	}
	return applied
}

// text is a hosted record as the dns package holds it.
func text(r zones.Record) (dns.RR, error) {
	b := make([]byte, 0, len(r.Owner)+10+len(r.RData))
	b = append(b, r.Owner...)
	b = binary.BigEndian.AppendUint16(b, r.Type)
	b = binary.BigEndian.AppendUint16(b, dns.ClassINET)
	b = binary.BigEndian.AppendUint32(b, r.TTL)
	b = binary.BigEndian.AppendUint16(b, uint16(len(r.RData)))
	b = append(b, r.RData...)
	rr, _, err := dns.UnpackRR(b, 0)
	return rr, err
}

// address is an A or AAAA record's address ("" for another type).
func address(rr dns.RR) string {
	switch a := rr.(type) {
	case *dns.A:
		return a.A.String()
	case *dns.AAAA:
		return a.AAAA.String()
	}
	return ""
}

func addOnce(l []string, s string) []string {
	if slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}

// ---- the query log: devices and sites ----

func (s *search) queryLog() error {
	if s.in.Log == nil {
		return nil
	}
	names, clients := s.in.Log.Asked(
		func(n string) bool { return rank(n, s.q) >= 0 },
		func(c string) bool { _, ok := s.devices[c]; return ok || rank(c, s.q) >= 0 })
	for _, a := range clients {
		r, what := rank(a.Value, s.q), "address"
		if d, ok := s.devices[a.Value]; ok && (r < 0 || d < r) {
			r, what = d, "name"
		}
		title := a.Value
		if hs := s.hosts[a.Value]; len(hs) > 0 {
			slices.Sort(hs)
			title = hs[0]
		}
		last := a.Last
		s.add(Result{Type: TypeDevice, Title: title, Text: a.Value + ": " + asked(a), Page: PageQueryLog, Key: a.Value,
			Link: link(PageQueryLog, "client", a.Value), Match: what, Queries: a.Queries, Blocked: a.Blocked, Last: &last, rank: r})
	}
	for _, a := range names {
		last := a.Last
		s.add(Result{Type: TypeSite, Title: a.Value, Text: asked(a), Page: PageQueryLog, Key: a.Value,
			Link: link(PageQueryLog, "name", a.Value), Match: "name", Queries: a.Queries, Blocked: a.Blocked, Last: &last,
			rank: rank(a.Value, s.q)})
	}
	return nil
}

func asked(a observe.Asked) string {
	t := "asked " + times(a.Queries)
	if a.Blocked > 0 {
		t += ", blocked " + times(a.Blocked)
	}
	return t + " in the query log the controller holds"
}

func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return strconv.Itoa(n) + " times"
}

// ---- check a site ----

// check offers Blocking's "check a site" for a query that is a site's name whole (not an
// address).
func (s *search) check() error {
	name, ok := blocklist.Canon(s.q)
	if !ok || net.ParseIP(s.q) != nil {
		return nil
	}
	s.add(Result{Type: TypeCheck, Title: name, Text: "check whether it is blocked, and by which list", Page: PageBlocking,
		Key: name, Link: link(PageBlocking, "check", name), Match: "typed", rank: 1})
	return nil
}

// ---- rules: the allowed and blocked sites ----

func (s *search) rules() error {
	var problems []string
	for _, f := range []struct{ file, state, text string }{
		{blocking.OverridesAllow, "allow", "always allowed"},
		{blocking.OverridesBlock, "block", "always blocked"},
	} {
		v, err := s.view(changes.Source, f.file)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !v.Exists {
			continue
		}
		var es []blocklist.Entry
		if _, err := blocklist.Parse(bytes.NewReader(v.Text), blocklist.Wildcard, func(e blocklist.Entry) { es = append(es, e) }); err != nil {
			problems = append(problems, f.file+": "+err.Error())
		}
		var applied map[string]bool // the names in the file as it is, when changes are pending
		if len(v.Pending) > 0 {
			applied = map[string]bool{}
			if cur, err := changes.Current(s.in.DataDir, changes.Source, f.file); err == nil && cur.Exists {
				blocklist.Parse(bytes.NewReader(cur.Text), blocklist.Wildcard, func(e blocklist.Entry) { applied[e.Name] = true })
			}
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		for i, e := range es {
			if s.late(i) {
				return s.ctx.Err()
			}
			r, what := rank(e.Name, s.q), "name"
			if r < 0 && strings.HasSuffix(s.q, "."+e.Name) {
				r, what = 1, "covers"
			}
			if r < 0 {
				continue
			}
			s.add(Result{Type: TypeRule, Title: e.Name, Text: f.text + ", with its subdomains", Page: PageBlocking, Key: e.Name,
				Link: link(PageBlocking, "site", e.Name), Match: what, State: f.state, Pending: applied != nil && !applied[e.Name], rank: r})
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// ---- lists ----

func (s *search) lists() error {
	v, err := s.view(changes.Lists, blocking.DefsFile)
	if err != nil || !v.Exists {
		return err
	}
	defs, err := blocking.Parse(v.Text)
	if err != nil {
		return fmt.Errorf("%s: %w", blocking.DefsFile, err)
	}
	var applied map[string]string // each list as it is now (JSON), when changes are pending
	if len(v.Pending) > 0 {
		applied = map[string]string{}
		if cur, err := changes.Current(s.in.DataDir, changes.Lists, blocking.DefsFile); err == nil && cur.Exists {
			if cd, err := blocking.Parse(cur.Text); err == nil {
				for _, l := range cd.Lists {
					b, _ := json.Marshal(l)
					applied[l.Name] = string(b)
				}
			}
		}
	}
	for _, l := range defs.Lists {
		r, what := rank(l.Name, s.q), "name"
		via := ""
		// A URL as the pages show it: a credential in it is never matched or returned.
		redact := l.Redactor()
		for _, spec := range append(append([]string{}, l.Sources...), l.Allow...) {
			shown := redact.Replace(spec)
			if x := rank(shown, s.q); x >= 0 {
				x = max(x, 1) // a source is never the list itself
				if r < 0 || x < r {
					r, what, via = x, "source", shown
				}
			}
		}
		if r < 0 {
			continue
		}
		text := "a blocklist from " + plural(len(l.Sources), "source") + ", " + plural(len(l.Allow), "allow source")
		if via != "" {
			text += "; reads " + via
		}
		s.add(Result{Type: TypeList, Title: l.Name, Text: text, Page: PageBlocking, Key: l.Name,
			Link: link(PageBlocking, "list", l.Name), Match: what, Pending: applied != nil && !sameList(applied, l), rank: r})
	}
	return nil
}

// sameList says whether l is as it is now (applied: each list's JSON).
func sameList(applied map[string]string, l blocking.List) bool {
	b, _ := json.Marshal(l)
	cur, ok := applied[l.Name]
	return ok && cur == string(b)
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// ---- the pending changes ----

func (s *search) changes() error {
	if s.in.Changes == nil {
		return nil
	}
	cs, err := s.in.Changes.List()
	if err != nil {
		return err
	}
	for _, c := range cs {
		fields := [][2]string{{"summary", c.Summary}, {"file", c.Name}, {"firmware", c.Firmware}}
		for _, n := range c.Nodes {
			fields = append(fields, [2]string{"node", n})
		}
		r, what := best(s.q, fields...)
		if r < 0 {
			continue
		}
		text := "pending: "
		switch {
		case c.Kind == changes.Firmware:
			text += "a firmware update of " + plural(len(c.Nodes), "node")
		case c.Delete:
			text += "deletes " + c.Name
		default:
			text += "changes " + c.Name
		}
		s.add(Result{Type: TypeChange, Title: c.Summary, Text: text, Page: PageChanges, Key: c.ID,
			Link: link(PageChanges, "change", c.ID), Match: what, Pending: true, rank: max(r, 1)})
	}
	return nil
}
