// Package fleet works on espDNS nodes as a set: finding them (mDNS and the settings list),
// reading their state, changing them one at a time without ever taking the last healthy
// node (docs/design.md, Principles), firmware updates that wait for the node to confirm
// the new build, and adoption. The espdns CLI is a thin layer over it; the controller
// wraps it too.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Client reads nodes and, with a Pusher, changes them.
type Client struct {
	Pusher  *release.Pusher // signs and sends releases; nil for reads only
	HTTP    *http.Client    // for /status and /health; nil: a 3 s timeout
	DNS     Resolver        // nil: UDP to port 53 of the node
	PeerDNS Resolver        // for DNS peers; nil: UDP to the peer's address (and port)
	Poll    time.Duration   // how often waits poll; 0: 1 s
	Logf    func(format string, args ...any)
	// Progress, if set, hears where a rolling push is with each node (Rollout), for the
	// controller to show per node. It only listens: a rollout is the same without it.
	Progress func(host string, step Step, detail string)
}

// Step is where a rolling push is with one node, as Client.Progress hears it.
type Step string

const (
	StepGate      Step = "gate"       // the rule: another node or a DNS peer answering, the others healthy
	StepWouldPush Step = "would-push" // a dry run: the rule passed; detail: where a list would go
	StepPushing   Step = "pushing"
	StepRebooting Step = "rebooting"
	StepChecking  Step = "checking" // waiting for it to be in service with the change, and its DNS checks
	StepChecked   Step = "checked"  // in service, the DNS checks passed
	StepSkipped   Step = "skipped"  // it already runs the build
	StepSoaking   Step = "soaking"  // detail: how long
	StepDone      Step = "done"
	// A list rollout that failed sends each node that took the list back (Result.Reverted):
	StepReverting   Step = "reverting"    // the revert command sent, or about to be
	StepReverted    Step = "reverted"     // back on the copy it had; detail: which
	StepNotReverted Step = "not-reverted" // detail: why, and the way on
)

// progress tells Progress; a listener that panics is logged and ignored, so it can't end
// a rollout part way (between a node's push and its reboot, say).
func (c *Client) progress(host string, s Step, detail string) {
	if c.Progress == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			c.logf("%s: progress listener: %v (ignored)", host, p)
		}
	}()
	c.Progress(host, s, detail)
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 3 * time.Second}
}

func (c *Client) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return time.Second
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (c *Client) dns() Resolver {
	if c.DNS != nil {
		return c.DNS
	}
	return UDP{}
}

// sleep waits d, or returns ctx's error.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get reads a JSON document from the node and returns its HTTP status.
func (c *Client) get(ctx context.Context, host, path string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, fmt.Errorf("%s%s: %s", host, path, resp.Status)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return resp.StatusCode, fmt.Errorf("%s%s: %s: %w", host, path, resp.Status, err)
	}
	return resp.StatusCode, nil
}

// Status reads the node's /status.
func (c *Client) Status(ctx context.Context, host string) (release.NodeStatus, error) {
	var st release.NodeStatus
	code, err := c.get(ctx, host, "/status", &st)
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("%s/status: %d", host, code)
	}
	return st, err
}

// Stored is one stored input as /health reports it.
type Stored struct {
	State  string `json:"state"`
	Seq    uint64 `json:"seq"`
	SHA256 string `json:"sha256"`
}

// Health is a node's /health (docs/design.md, Health and fault indication).
type Health struct {
	Code      int      `json:"-"` // /health's HTTP status: 200 while answering, else 503
	Legacy    bool     `json:"-"` // firmware from before /health: made up from /status
	State     string   `json:"state"`
	Answering bool     `json:"answering"`
	Reasons   []string `json:"reasons"`
	UptimeS   int64    `json:"uptime_s"`
	BootMS    int      `json:"boot_ms"`
	Blocklist *Stored  `json:"blocklist"`
	Overrides *Stored  `json:"overrides"`
	Zones     *Stored  `json:"zones"`
}

// Health reads the node's /health. A node on firmware from before /health has its state
// made up from /status: healthy, or degraded if it says so, and answering if it answers.
func (c *Client) Health(ctx context.Context, host string) (Health, error) {
	var h Health
	code, err := c.get(ctx, host, "/health", &h)
	if code != http.StatusNotFound {
		h.Code = code
		return h, err
	}
	st, err := c.Status(ctx, host)
	if err != nil {
		return h, err
	}
	h = Health{Code: http.StatusOK, Legacy: true, State: "healthy", Answering: true, UptimeS: st.UptimeS, BootMS: st.BootMS}
	switch {
	case st.Health != nil:
		h.State, h.Answering, h.Reasons = st.Health.State, st.Health.Answering, st.Health.Reasons
	case st.Degraded:
		h.State, h.Reasons = "degraded", []string{"degraded"}
	}
	return h, nil
}

// InService says whether the node is answering and healthy, or degraded only for reasons
// in allowed (for example, ones it had before a change).
func (h Health) InService(allowed []string) error {
	switch {
	case h.Code != http.StatusOK || !h.Answering:
		return fmt.Errorf("not answering (%s, /health %d)", h.describe(), h.Code)
	case h.State == "healthy":
		return nil
	case h.State == "degraded":
		var bad []string
		for _, r := range h.Reasons {
			if !slices.Contains(allowed, r) {
				bad = append(bad, r)
			}
		}
		if len(bad) == 0 {
			return nil
		}
		return fmt.Errorf("degraded: %s", strings.Join(bad, ", "))
	}
	return fmt.Errorf("%s", h.describe())
}

func (h Health) describe() string {
	if len(h.Reasons) == 0 {
		return h.State
	}
	return h.State + ": " + strings.Join(h.Reasons, ", ")
}

// Node is one node as Discover finds it.
type Node struct {
	Addr   string              `json:"addr"`
	Source string              `json:"source"` // "mdns", "settings" or both ("mdns,settings")
	Advert *nodes.Advert       `json:"advert,omitempty"`
	Status *release.NodeStatus `json:"status,omitempty"`
	Health *Health             `json:"health,omitempty"`
	Error  string              `json:"error,omitempty"`
}

// Discover lists the nodes found over mDNS within window (none if window is 0) and the
// listed addresses, each with its /status and /health.
func (c *Client) Discover(ctx context.Context, window time.Duration, listed []string) ([]Node, error) {
	byAddr := map[string]*Node{}
	if window > 0 {
		ads, err := nodes.Browse(ctx, window)
		if err != nil {
			return nil, fmt.Errorf("mdns: %w", err)
		}
		for _, a := range ads {
			byAddr[a.Addr] = &Node{Addr: a.Addr, Source: "mdns", Advert: &a}
		}
	}
	for _, a := range listed {
		if n, ok := byAddr[a]; ok {
			n.Source += ",settings"
		} else {
			byAddr[a] = &Node{Addr: a, Source: "settings"}
		}
	}
	var wg sync.WaitGroup
	for _, n := range byAddr {
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			c.Fill(ctx, n)
		}(n)
	}
	wg.Wait()
	out := make([]Node, 0, len(byAddr))
	for _, n := range byAddr {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out, nil
}

// Adopted says whether the node runs on a pushed config (adopt put its address there), so
// it is in the router's DNS list and clients use it.
func Adopted(n Node) bool {
	if n.Status != nil && n.Status.Config != nil {
		return n.Status.Config.Source == "node"
	}
	return n.Advert != nil && n.Advert.Adopted
}

// Count sets which of the nodes known (Discover's) count for the plan's rule: every other
// node clients use is a peer; a node found but not adopted isn't in the router's DNS list,
// so clients don't use it and it doesn't count (named counts it anyway: the CLI's -peer).
// The same for a target: changed, but while another node is changed it doesn't count.
func (c *Client) Count(ctx context.Context, p *Plan, known []Node, named []string) {
	for _, t := range p.Targets {
		i := slices.IndexFunc(known, func(n Node) bool { return n.Addr == t })
		n := Node{Addr: t}
		if i >= 0 {
			n = known[i]
		} else {
			c.Fill(ctx, &n)
		}
		if !Adopted(n) && !slices.Contains(named, t) {
			c.logf("%s not counted as answering while another node is changed: not adopted (no node config)", t)
			p.Uncounted = append(p.Uncounted, t)
		}
	}
	for _, n := range known {
		switch {
		case slices.Contains(p.Targets, n.Addr):
		case slices.Contains(named, n.Addr) || Adopted(n):
			p.Peers = append(p.Peers, n.Addr)
		default:
			c.logf("%s not counted as a peer: not adopted (no node config)", n.Addr)
		}
	}
	if len(p.Peers) > 0 {
		c.logf("other nodes: %s", strings.Join(p.Peers, ", "))
	}
}

// Fill reads n's /status and /health.
func (c *Client) Fill(ctx context.Context, n *Node) {
	st, err := c.Status(ctx, n.Addr)
	if err != nil {
		n.Error = err.Error()
		return
	}
	n.Status = &st
	h, err := c.Health(ctx, n.Addr)
	if err != nil {
		n.Error = err.Error()
		return
	}
	n.Health = &h
}
