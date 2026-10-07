package observe

// The fleet's query log in the controller: each node's /querylog read with its cursor
// (fleet.ReadQueryLog: a reboot starts it over) into one buffer of at most LogCap entries,
// the oldest dropped first. The client addresses are the node's: masked there by its
// "querylog": {"client"} setting, and masked here too (never unmasked) when a node's
// setting turns stricter, so what the buffer held from before is not shown either.

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// LogCap is the most query log entries the controller holds, over every node. An entry is
// 200 bytes and its strings, about 300 with a typical name (a name is at most 124 bytes on
// the node, escaped as in a zone file up to 4 times that): about 6 MB, 15 MB at most.
const LogCap = 20000

// Entry is one query from a node's log, as the controller holds it.
type Entry struct {
	ID        uint64    `json:"id"`   // the controller's, in the order read: the follow cursor
	Node      string    `json:"node"` // the node's key (its ID, else its address)
	At        time.Time `json:"at"`   // the node's clock, else estimated from its uptime
	Estimated bool      `json:"estimated,omitempty"`
	release.QueryEntry
}

// logRing is the buffer: the newest LogCap entries, oldest first.
type logRing struct {
	buf  []Entry
	head int // the next slot written once full
}

func (r *logRing) add(e Entry) {
	if len(r.buf) < LogCap {
		r.buf = append(r.buf, e)
		return
	}
	r.buf[r.head] = e
	r.head = (r.head + 1) % LogCap
}

// each calls f on every entry, oldest first.
func (r *logRing) each(f func(*Entry)) {
	n := len(r.buf)
	for i := 0; i < n; i++ {
		f(&r.buf[(r.head+i)%n])
	}
}

// strictness orders the client settings: full, subnet, hidden.
func strictness(mode string) int {
	switch mode {
	case "full":
		return 0
	case "subnet":
		return 1
	default:
		return 2 // hidden, or one this controller doesn't know: the strictest
	}
}

// mask applies a client setting to an address as the node does (firmware qlog.c
// ql_client_addr): subnet keeps its /24, hidden none.
func mask(client *string, mode string) *string {
	switch strictness(mode) {
	case 0:
		return client
	case 1:
		if client == nil {
			return nil
		}
		ip := net.ParseIP(*client).To4()
		if ip == nil {
			return nil // not an IPv4 address: nothing safe to keep
		}
		s := net.IPv4(ip[0], ip[1], ip[2], 0).String()
		return &s
	default:
		return nil
	}
}

// Filter picks entries from the buffer.
type Filter struct {
	Node   string // the node's key, exactly
	Client string // in the client address
	Name   string // in the name, either case
	Result string // exactly
	QType  string // exactly, either case
	After  uint64 // only entries read after this ID (follow)
	Run    string // the run After is from (LogView.Run): another run's is taken as 0
	Limit  int    // the newest this many (default 200, at most 1000)
}

func (f Filter) match(e *Entry) bool {
	if e.ID <= f.After || f.Node != "" && e.Node != f.Node || f.Result != "" && e.Result != f.Result ||
		f.QType != "" && !strings.EqualFold(e.QType, f.QType) {
		return false
	}
	if f.Client != "" && (e.Client == nil || !strings.Contains(*e.Client, f.Client)) {
		return false
	}
	return f.Name == "" || strings.Contains(strings.ToLower(e.QName), strings.ToLower(f.Name))
}

// LogView is a read of the buffer.
type LogView struct {
	Entries []Entry    `json:"entries"` // newest first, by time
	Run     string     `json:"run"`     // this run of the controller: IDs start over with each
	Last    uint64     `json:"last"`    // the newest ID read: the next follow's after
	Matched int        `json:"matched"` // entries that matched (Entries is the newest Limit of them)
	Held    int        `json:"held"`    // entries in the buffer
	Cap     int        `json:"cap"`
	Oldest  *time.Time `json:"oldest"` // the buffer's span
	Newest  *time.Time `json:"newest"`
	Nodes   []LogNode  `json:"nodes"` // each node's query log, as last read
}

// LogNode is one node's query log state.
type LogNode struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Addr string `json:"addr"`
	QLState
}

// QLState is how reading a node's query log goes.
type QLState struct {
	// State: "" (not read yet), "ok", "unsupported" (firmware from before the query log),
	// "error" (the last read failed: Error).
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
	Enabled  bool   `json:"enabled"`  // the node's query log runs
	Client   string `json:"client"`   // its client setting: full, subnet or hidden
	Capacity uint32 `json:"capacity"` // its ring
	Read     uint64 `json:"read"`     // entries read since the controller started
	Lost     uint64 `json:"lost"`     // entries it overwrote before they were read
	Skipped  uint64 `json:"skipped"`  // older entries not read: the first read starts at its newest
	Restarts int    `json:"restarts"` // boots seen: its log started over
	Behind   bool   `json:"behind"`   // it held more than the last poll read
	// LastRead is the last good read.
	LastRead time.Time `json:"last_read"`
}

// TopName is a name and how often it was asked.
type TopName struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Top is the names asked most in the buffer.
type Top struct {
	Entries int        `json:"entries"` // entries counted
	Oldest  *time.Time `json:"oldest"`  // their span
	Newest  *time.Time `json:"newest"`
	Queried []TopName  `json:"queried"`
	Blocked []TopName  `json:"blocked"` // result blocked or overridden
	Blocks  int        `json:"blocks"`  // blocked entries counted (both)
}

// TopN is how many names Top lists.
const TopN = 10

func top(counts map[string]int) []TopName {
	out := make([]TopName, 0, len(counts))
	for n, c := range counts {
		out = append(out, TopName{n, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > TopN {
		out = out[:TopN]
	}
	return out
}

// Asked is one name, or one client, in the buffer: how often, how often blocked (by the
// blocklist or the overrides) and when last.
type Asked struct {
	Value   string    `json:"value"` // the name (lowercase) or the client address
	Queries int       `json:"queries"`
	Blocked int       `json:"blocked"`
	Last    time.Time `json:"last"`
}

// Asked counts, in one pass over the buffer, the names (lowercase) name says yes to and the
// clients client says yes to, each sorted by queries (the most first), then by value. A nil
// func picks none. What it returns is bounded by the buffer (LogCap entries).
func (s *Store) Asked(name, client func(string) bool) (names, clients []Asked) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nm, cm := map[string]*Asked{}, map[string]*Asked{}
	count := func(m map[string]*Asked, v string, e *Entry) {
		a := m[v]
		if a == nil {
			a = &Asked{Value: v}
			m[v] = a
		}
		a.Queries++
		if Blocks(e.Result) {
			a.Blocked++
		}
		if e.At.After(a.Last) {
			a.Last = e.At
		}
	}
	s.log.each(func(e *Entry) {
		if name != nil {
			if n := strings.ToLower(e.QName); name(n) {
				count(nm, n, e)
			}
		}
		if client != nil && e.Client != nil && client(*e.Client) {
			count(cm, *e.Client, e)
		}
	})
	return sortAsked(nm), sortAsked(cm)
}

func sortAsked(m map[string]*Asked) []Asked {
	out := make([]Asked, 0, len(m))
	for _, a := range m {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Queries != out[j].Queries {
			return out[i].Queries > out[j].Queries
		}
		return out[i].Value < out[j].Value
	})
	return out
}
