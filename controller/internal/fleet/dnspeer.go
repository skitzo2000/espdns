package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// DNSPeer is a resolver clients use besides the nodes (a Technitium server, say). It is
// never changed and has no /health: it counts as one healthy answering peer for the
// last-healthy-node rule when, each time the rule is checked (right before a node is
// changed or rebooted), it passes the DNS checks: a forwarded name resolves and its zones
// answer their SOA authoritatively.
type DNSPeer struct {
	Addr string // address, or address:port for a DNS port other than 53
	// Zones are zone apexes it must answer for; empty: the secondary zones of the node
	// about to be changed (the peer is their primary), if it reports any.
	Zones []string
	// Forwarded names it must resolve; empty: the plan's forwarded checks, else example.com.
	Forwarded []string
}

// peerDNS is the resolver for DNS peers: UDP to the peer's own DNS port.
func (c *Client) peerDNS() *Client {
	cc := *c
	if c.PeerDNS != nil {
		cc.DNS = c.PeerDNS
	} else {
		cc.DNS = UDP{KeepPort: true}
	}
	return &cc
}

// checkDNSPeer runs the peer's checks; host is the node about to be changed. A peer that
// is that node itself (its address on DNS port 53) never counts: it would answer the
// checks right up to the reboot. Without the node's status (for its address and zones)
// the peer doesn't count either.
func (c *Client) checkDNSPeer(ctx context.Context, p Plan, host string, d DNSPeer) error {
	st, err := c.Status(ctx, host)
	if err != nil {
		return fmt.Errorf("no status of %s to check it against: %w", host, err)
	}
	if c.sameNode(ctx, d.Addr, host, st.IP) {
		return errors.New("it is the node being changed")
	}
	var zones []string
	for _, z := range st.Zones {
		if !z.Expired && !slices.Contains(zones, z.Name) {
			zones = append(zones, z.Name)
		}
	}
	return c.CheckDNSPeer(ctx, d, zones, p.Checks.Forwarded)
}

// CheckDNSPeer runs a DNS peer's checks: the SOA of its zones (else of zones, the
// secondary zones of the node about to be changed) answered authoritatively, and its
// forwarded names (else forwarded, else example.com) resolved.
func (c *Client) CheckDNSPeer(ctx context.Context, d DNSPeer, zones, forwarded []string) error {
	ch := Checks{Zones: d.Zones, Forwarded: d.Forwarded}
	if len(ch.Forwarded) == 0 {
		ch.Forwarded = forwarded
	}
	if len(ch.Forwarded) == 0 {
		ch.Forwarded = []string{"example.com"}
	}
	if len(ch.Zones) == 0 {
		ch.Zones = zones
	}
	// No status or health: Local stays empty and the blocked checks are off, so only
	// Zones and Forwarded are asked.
	return c.peerDNS().CheckDNS(ctx, d.Addr, release.NodeStatus{}, Health{}, ch)
}

// sameNode says whether the DNS peer at peer (address, or address:port) is the node at
// host (whose port, if any, is HTTP) reporting ip: the same address, on DNS port 53.
func (c *Client) sameNode(ctx context.Context, peer, host, ip string) bool {
	ph, port, err := net.SplitHostPort(peer)
	if err != nil {
		ph, port = peer, "53"
	}
	if port != "53" {
		return false
	}
	nh := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		nh = h
	}
	addrs := func(h string) []string {
		out := []string{strings.ToLower(strings.TrimSuffix(h, "."))}
		if a, err := net.DefaultResolver.LookupHost(ctx, h); err == nil {
			out = append(out, a...)
		}
		return out
	}
	node := addrs(nh)
	if ip != "" {
		node = append(node, ip)
	}
	for _, a := range addrs(ph) {
		if slices.Contains(node, a) {
			return true
		}
	}
	return false
}
