package release

import "time"

// QueryLogStatus is /status's "querylog" (firmware querylog.h): the service, its ring and
// the node config's settings for it.
type QueryLogStatus struct {
	Enabled  bool   `json:"enabled"`  // the node config has it on
	State    string `json:"state"`    // off, starting, running, failed (off also with no memory.querylog_kb)
	Client   string `json:"client"`   // full, subnet or hidden: how much of a client's address it keeps
	Capacity uint32 `json:"capacity"` // queries the ring holds
	Entries  uint64 `json:"entries"`  // queries in it now
	Oldest   uint64 `json:"oldest"`   // the oldest seq held
	Newest   uint64 `json:"newest"`   // the newest seq (0: none since boot)
	BootID   string `json:"boot_id"`  // changes at every boot, when the seqs start over at 1
}

// QueryEntry is one query in a node's query log (firmware qlog.h).
type QueryEntry struct {
	Seq       uint64  `json:"seq"`
	UptimeMS  uint64  `json:"uptime_ms"`
	Time      *int64  `json:"time"`   // Unix ms; nil until the node's clock was set
	Client    *string `json:"client"` // nil when the node keeps no address ("client": "hidden")
	Transport string  `json:"transport"`
	QName     string  `json:"qname"`
	QType     string  `json:"qtype"`
	// Result: cache, forwarded, hosted, secondary, blocked, overridden, refused, servfail,
	// error, notify.
	Result    string `json:"result"`
	RCode     string `json:"rcode"`
	LatencyUS uint32 `json:"latency_us"`
	Rule      string `json:"rule,omitempty"` // list, override, cname (blocked), allow (by the overrides)
	Truncated bool   `json:"truncated,omitempty"`
}

// When is the entry's time, from the node's clock; else, with the page it came in, from
// the node's uptime against this machine's clock (approximate).
func (e QueryEntry) When(p QueryLogPage, now time.Time) time.Time {
	if e.Time != nil {
		return time.UnixMilli(*e.Time)
	}
	if p.UptimeMS >= e.UptimeMS {
		return now.Add(-time.Duration(p.UptimeMS-e.UptimeMS) * time.Millisecond)
	}
	return now
}

// QueryLogPage is one GET /querylog reply.
type QueryLogPage struct {
	BootID   string       `json:"boot_id"`
	Enabled  bool         `json:"enabled"`
	State    string       `json:"state"`
	Client   string       `json:"client"`
	Capacity uint32       `json:"capacity"`
	Oldest   uint64       `json:"oldest"`
	Newest   uint64       `json:"newest"`
	Cursor   uint64       `json:"cursor"`
	UptimeMS uint64       `json:"uptime_ms"`
	Time     *int64       `json:"time"`
	Entries  []QueryEntry `json:"entries"`
	// Next is the cursor for the next page; Lost the entries after Cursor overwritten before
	// they were read; Reset: Cursor was past the newest (from before a reboot), so the page
	// starts at the oldest held; More: entries after Next are held already.
	Next  uint64 `json:"next"`
	Lost  uint64 `json:"lost"`
	Reset bool   `json:"reset"`
	More  bool   `json:"more"`
}

// QueryLogLimit is the most entries a node returns in one page.
const QueryLogLimit = 1000
