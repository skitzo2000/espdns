package main

// espdns metrics and espdns querylog (docs/design.md, Observability): a node's /metrics and
// its query log, read only. Firmware from before them says so ("not supported").

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// espdns metrics -host H [-raw]
func cmdMetrics(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ExitOnError)
	host := fs.String("host", "", "the node's address")
	raw := fs.Bool("raw", false, "print /metrics as the node sends it (the Prometheus text format)")
	asJSON := fs.Bool("json", false, "print the parsed metrics as JSON")
	fs.Parse(args)
	if err := needHost(*host); err != nil {
		return err
	}
	c := &fleet.Client{}
	m, err := c.Metrics(context.Background(), *host)
	if err != nil {
		return err
	}
	switch {
	case *raw:
		_, err = io.WriteString(os.Stdout, m.Text)
		return err
	case *asJSON:
		return printJSON(m)
	}
	printMetrics(os.Stdout, *host, m)
	return nil
}

// printMetrics is a summary of a node's metrics.
func printMetrics(w io.Writer, host string, m fleet.Metrics) {
	v := func(name string, kv ...string) float64 { x, _ := m.Value(name, kv...); return x }
	fmt.Fprintf(w, "%s:", host)
	for st, x := range m.ByLabel("espdns_health_state", "state") {
		if x == 1 {
			fmt.Fprintf(w, " %s", st)
		}
	}
	if b, ok := m.Value("espdns_build_info"); ok && b == 1 {
		s := m.Family("espdns_build_info").Samples[0].Labels
		fmt.Fprintf(w, ", firmware %s on %s (%s)", s["version"], s["board"], s["image"])
	}
	fmt.Fprintf(w, ", up %s\n", (time.Duration(v("espdns_uptime_seconds")) * time.Second).String())
	var reasons []string
	for r, x := range m.ByLabel("espdns_health_reason", "reason") {
		if x == 1 {
			reasons = append(reasons, r)
		}
	}
	if len(reasons) > 0 {
		sort.Strings(reasons)
		fmt.Fprintf(w, "  reasons: %s\n", strings.Join(reasons, ", "))
	}
	byResult := m.ByLabel("espdns_queries_total", "result")
	total := 0.0
	for _, x := range byResult {
		total += x
	}
	fmt.Fprintf(w, "  queries %.0f (udp %.0f, tcp %.0f):", total, v("espdns_queries_received_total", "transport", "udp"),
		v("espdns_queries_received_total", "transport", "tcp"))
	for _, r := range []string{"cache", "forwarded", "hosted", "secondary", "blocked", "overridden", "refused",
		"servfail", "error", "notify", "dropped"} {
		if x := byResult[r]; x > 0 {
			fmt.Fprintf(w, " %s %.0f", r, x)
		}
	}
	fmt.Fprintln(w)
	if p50, ok := m.Quantile("espdns_query_duration_seconds", 0.5); ok {
		p99, _ := m.Quantile("espdns_query_duration_seconds", 0.99)
		fmt.Fprintf(w, "  answer time p50 %s, p99 %s (estimated from the histogram)\n", secs(p50), secs(p99))
	}
	var rcodes []string
	for rc, x := range m.ByLabel("espdns_responses_total", "rcode") {
		if x > 0 {
			rcodes = append(rcodes, fmt.Sprintf("%s %.0f", rc, x))
		}
	}
	if len(rcodes) > 0 {
		sort.Strings(rcodes)
		fmt.Fprintf(w, "  rcodes: %s\n", strings.Join(rcodes, ", "))
	}
	if f := m.Family("espdns_upstream_queries_total"); f != nil {
		for _, s := range f.Samples {
			up := s.Labels["upstream"]
			line := fmt.Sprintf("  forwarder %s: %.0f asked, %.0f failed", up, s.Value,
				v("espdns_upstream_failures_total", "upstream", up))
			if to, ok := m.Value("espdns_upstream_timeouts_total", "upstream", up); ok {
				line += fmt.Sprintf(" (%.0f timed out)", to)
			}
			if p50, ok := m.Quantile("espdns_upstream_duration_seconds", 0.5, "upstream", up); ok {
				p95, _ := m.Quantile("espdns_upstream_duration_seconds", 0.95, "upstream", up)
				line += ", answer p50 " + secs(p50) + ", p95 " + secs(p95)
			}
			fmt.Fprintln(w, line)
		}
	}
	if slots, ok := m.Value("espdns_fwd_slots"); ok {
		fmt.Fprintf(w, "  upstream queries: %.0f in flight to the forwarders, %.0f to forward zones (each at most %.0f), peak %.0f of %.0f\n",
			v("espdns_fwd_inflight", "group", "default"), v("espdns_fwd_inflight", "group", "zones"),
			v("espdns_fwd_group_cap"), v("espdns_fwd_inflight_peak"), slots)
		fmt.Fprintf(w, "  shed %.0f (forwarders %.0f, zones %.0f), unanswered %.0f, TCP retries %.0f, select errors %.0f\n",
			m.Sum("espdns_fwd_shed_total"), v("espdns_fwd_shed_total", "group", "default"),
			v("espdns_fwd_shed_total", "group", "zones"), m.Sum("espdns_fwd_expired_total"),
			v("espdns_fwd_tcp_retries_total"), v("espdns_fwd_select_errors_total"))
	}
	if _, ok := m.Value("espdns_cache_entries"); ok {
		hits, misses := v("espdns_cache_hits_total"), v("espdns_cache_misses_total")
		rate := 0.0
		if hits+misses > 0 {
			rate = 100 * hits / (hits + misses)
		}
		fmt.Fprintf(w, "  cache %.0f of %.0f answers, %.0f%% hits, %.0f evicted\n", v("espdns_cache_entries"),
			v("espdns_cache_entries_max"), rate, v("espdns_cache_evictions_total"))
	}
	if _, ok := m.Value("espdns_blocklist_entries", "list", "blocklist"); ok {
		fmt.Fprintf(w, "  blocklist seq %.0f, %.0f entries; overrides seq %.0f, %.0f entries\n",
			v("espdns_blocklist_seq", "list", "blocklist"), v("espdns_blocklist_entries", "list", "blocklist"),
			v("espdns_blocklist_seq", "list", "overrides"), v("espdns_blocklist_entries", "list", "overrides"))
	}
	if f := m.Family("espdns_service_state"); f != nil {
		var svcs []string
		for _, s := range f.Samples {
			line := s.Labels["service"] + " " + s.Labels["state"]
			if p, ok := m.Value("espdns_service_memory_planned_bytes", "service", s.Labels["service"]); ok && p > 0 {
				line += fmt.Sprintf(" (%.0f KB)", p/1024)
			}
			svcs = append(svcs, line)
		}
		fmt.Fprintf(w, "  services: %s\n", strings.Join(svcs, ", "))
	}
	if c, ok := m.Value("espdns_querylog_capacity"); ok {
		fmt.Fprintf(w, "  query log %.0f of %.0f queries\n", v("espdns_querylog_entries"), c)
	}
}

func secs(s float64) string {
	return (time.Duration(s * float64(time.Second))).Round(10 * time.Microsecond).String()
}

// espdns querylog -host H [-follow] [-cursor N] [-json]
func cmdQueryLog(args []string) error {
	fs := flag.NewFlagSet("querylog", flag.ExitOnError)
	host := fs.String("host", "", "the node's address")
	follow := fs.Bool("follow", false, "keep reading new queries as they come (Ctrl-C ends it)")
	every := fs.Duration("every", 2*time.Second, "with -follow, how often to read")
	cursor := fs.Uint64("cursor", 0, "start after this seq (0: the oldest the node holds)")
	asJSON := fs.Bool("json", false, "one JSON object per query")
	fs.Parse(args)
	if err := needHost(*host); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	o := queryLogOpts{cursor: *cursor, follow: *follow, every: *every, json: *asJSON}
	if *asJSON {
		o.notes = os.Stderr // standard output stays one JSON object a line
	}
	err := runQueryLog(ctx, &fleet.Client{}, os.Stdout, *host, o)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

type queryLogOpts struct {
	cursor uint64
	follow bool
	every  time.Duration
	json   bool
	notes  io.Writer // the "# ..." lines; nil: with the queries
	pages  int       // stop after this many reads (tests); 0: no limit
}

// runQueryLog prints the node's query log from o.cursor: what it holds, then, with follow,
// what comes, until ctx ends.
func runQueryLog(ctx context.Context, c *fleet.Client, w io.Writer, host string, o queryLogOpts) error {
	cur := fleet.QueryLogCursor{Seq: o.cursor}
	enc := json.NewEncoder(w)
	notes := o.notes
	if notes == nil {
		notes = w
	}
	failing := false
	for reads := 1; ; reads++ {
		p, restarted, err := c.ReadQueryLog(ctx, host, &cur, release.QueryLogLimit)
		if err != nil {
			// Following, a node that doesn't answer for a while (rebooting, the network) is
			// waited for: its boot ID then says whether it rebooted. The first read, firmware
			// without a query log and the end of ctx still end it.
			if !o.follow || reads == 1 || errors.Is(err, fleet.ErrNotSupported) || ctx.Err() != nil {
				return err
			}
			if !failing {
				fmt.Fprintf(notes, "# %v: trying again every %s\n", err, o.every)
				failing = true
			}
			if o.pages > 0 && reads >= o.pages {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.every):
			}
			continue
		}
		if failing {
			fmt.Fprintf(notes, "# %s answers again\n", host)
			failing = false
		}
		if reads == 1 && p.State != "running" {
			fmt.Fprintf(notes, "# the query log is %s on %s (config querylog.enabled %v)\n", p.State, host, p.Enabled)
		}
		if restarted {
			fmt.Fprintf(notes, "# %s rebooted: its query log starts over (seq 1)\n", host)
		}
		if p.Lost > 0 {
			fmt.Fprintf(notes, "# %d queries lost: the node's ring (%d) overwrote them before they were read\n", p.Lost,
				p.Capacity)
		}
		now := time.Now()
		for _, e := range p.Entries {
			if o.json {
				enc.Encode(e)
				continue
			}
			fmt.Fprintln(w, queryLine(e, p, now))
		}
		if o.pages > 0 && reads >= o.pages {
			return nil
		}
		if p.More {
			continue
		}
		if !o.follow {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(o.every):
		}
	}
}

// queryLine is one query as a line: when, client, transport, type, name, result, rcode,
// time to answer.
func queryLine(e release.QueryEntry, p release.QueryLogPage, now time.Time) string {
	client := "-"
	if e.Client != nil {
		client = *e.Client
	}
	result := e.Result
	if e.Rule != "" {
		result += "(" + e.Rule + ")"
	}
	name := e.QName
	if e.Truncated {
		name = "..." + name
	}
	return fmt.Sprintf("%s  %-15s %s %-6s %-40s %-14s %-8s %s", e.When(p, now).Local().Format("2006-01-02 15:04:05.000"),
		client, e.Transport, e.QType, name, result, e.RCode,
		(time.Duration(e.LatencyUS) * time.Microsecond).String())
}
