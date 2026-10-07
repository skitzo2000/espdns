package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Resolver sends one DNS query to a node.
type Resolver interface {
	Exchange(ctx context.Context, host string, m *dns.Msg) (*dns.Msg, error)
}

// UDP queries port 53 of the node's address (any port in host is its HTTP one, dropped).
type UDP struct {
	Timeout time.Duration // 0: 2 s
	// KeepPort: a port in host is the DNS port (a DNS peer's address), not an HTTP one.
	KeepPort bool
}

func (u UDP) Exchange(ctx context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	addr := net.JoinHostPort(host, "53")
	if h, p, err := net.SplitHostPort(host); err == nil {
		if !u.KeepPort {
			p = "53"
		}
		addr = net.JoinHostPort(h, p)
	}
	c := &dns.Client{Net: "udp", Timeout: u.Timeout}
	if c.Timeout == 0 {
		c.Timeout = 2 * time.Second
	}
	r, _, err := c.ExchangeContext(ctx, m, addr)
	return r, err
}

// Checks are the DNS queries that show a node answers as it should after a change
// (docs/design.md, Blocking: checks before a push): a local name, a forwarded name, a
// blocked name and the must-resolve list.
type Checks struct {
	// Local names, answered from the node's own zones: NOERROR and authoritative. Empty:
	// the SOA of each zone the node reports (secondary and hosted).
	Local []string
	// Zones are zone apexes whose SOA must come back NOERROR and authoritative, besides
	// Local: a DNS peer's zones (it reports none of its own).
	Zones []string
	// Forwarded names: NOERROR with an answer that isn't a blocked one. On a node with
	// forwarding off, neither these nor Blocked nor MustResolve are checked.
	Forwarded []string
	// Blocked names: a blocked answer (0.0.0.0, ::, or NXDOMAIN), when the node's
	// blocklist is on.
	Blocked []string
	// MustResolve names: NOERROR with an answer that isn't a blocked one.
	MustResolve []string
	// Off skips every check but "it answers".
	Off bool
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

// exchange asks twice before giving up: one lost UDP packet isn't a failed node.
func (c *Client) exchange(ctx context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	var err error
	for range 2 {
		var r *dns.Msg
		if r, err = c.dns().Exchange(ctx, host, m); err == nil {
			return r, nil
		}
	}
	return nil, err
}

// Answers sends the node one query and wants any reply. That is also what confirms a
// config on trial (docs/design.md, Adoption, step 6).
func (c *Client) Answers(ctx context.Context, host string) error {
	_, err := c.exchange(ctx, host, query("espdns.check.invalid", dns.TypeA))
	return err
}

// blockedAnswer: NXDOMAIN, or an address answer of 0.0.0.0 or ::.
func blockedAnswer(r *dns.Msg) bool {
	if r.Rcode == dns.RcodeNameError {
		return true
	}
	for _, rr := range r.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if a.A.IsUnspecified() {
				return true
			}
		case *dns.AAAA:
			if a.AAAA.IsUnspecified() {
				return true
			}
		}
	}
	return false
}

// CheckDNS runs the checks against the node. st and h are its status and health: its
// zones are the default local names, and blocked names are checked only with its list on.
func (c *Client) CheckDNS(ctx context.Context, host string, st release.NodeStatus, h Health, ch Checks) error {
	if err := c.Answers(ctx, host); err != nil {
		return fmt.Errorf("no DNS answer: %w", err)
	}
	if ch.Off {
		return nil
	}
	var errs []string
	local := slices.Clone(ch.Local)
	if len(local) == 0 {
		for _, z := range st.Zones {
			if !z.Expired {
				local = append(local, z.Name)
			}
		}
		if st.Hosted != nil {
			for _, z := range st.Hosted.Zones {
				local = append(local, z.Name)
			}
		}
	}
	qtypes := map[string]uint16{}
	for _, n := range local {
		qtypes[n] = dns.TypeA
		if len(ch.Local) == 0 {
			qtypes[n] = dns.TypeSOA // a zone's apex
		}
	}
	for _, z := range ch.Zones {
		if _, ok := qtypes[z]; !ok {
			local = append(local, z)
		}
		qtypes[z] = dns.TypeSOA
	}
	for _, n := range local {
		r, err := c.exchange(ctx, host, query(n, qtypes[n]))
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("local %s: %v", n, err))
		case r.Rcode != dns.RcodeSuccess || !r.Authoritative:
			errs = append(errs, fmt.Sprintf("local %s: %s, authoritative %v", n, dns.RcodeToString[r.Rcode], r.Authoritative))
		}
	}
	resolves := func(what, n string) {
		r, err := c.exchange(ctx, host, query(n, dns.TypeA))
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("%s %s: %v", what, n, err))
		case blockedAnswer(r):
			errs = append(errs, fmt.Sprintf("%s %s: blocked (%s)", what, n, dns.RcodeToString[r.Rcode]))
		case r.Rcode != dns.RcodeSuccess || len(r.Answer) == 0:
			errs = append(errs, fmt.Sprintf("%s %s: %s with %d answers", what, n, dns.RcodeToString[r.Rcode], len(r.Answer)))
		}
	}
	// A node with forwarding off answers names it would forward REFUSED, by its config,
	// before any blocking: the forwarded, must-resolve and blocked checks don't apply.
	forwarding := !st.ServiceOff("forwarding")
	if forwarding {
		for _, n := range ch.Forwarded {
			resolves("forwarded", n)
		}
		for _, n := range ch.MustResolve {
			resolves("must-resolve", n)
		}
	}
	if forwarding && h.Blocklist != nil && h.Blocklist.State == "on" {
		for _, n := range ch.Blocked {
			r, err := c.exchange(ctx, host, query(n, dns.TypeA))
			switch {
			case err != nil:
				errs = append(errs, fmt.Sprintf("blocked %s: %v", n, err))
			case !blockedAnswer(r):
				errs = append(errs, fmt.Sprintf("blocked %s: not blocked (%s)", n, dns.RcodeToString[r.Rcode]))
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
