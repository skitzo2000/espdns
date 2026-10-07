package fleet

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// fakeResolver is a DNS server on loopback, as Technitium answers: authoritative for its
// zones, recursive for the rest. broken makes it answer SERVFAIL to everything.
type fakeResolver struct {
	addr  string
	zones []string
	mu    sync.Mutex
	asked []string // "name type"
	bad   bool
}

func newResolver(t *testing.T, zones ...string) *fakeResolver {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeResolver{addr: pc.LocalAddr().String(), zones: zones}
	srv := &dns.Server{PacketConn: pc, Handler: f}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	return f
}

func (f *fakeResolver) broken(b bool) {
	f.mu.Lock()
	f.bad = b
	f.mu.Unlock()
}

func (f *fakeResolver) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := m.Question[0]
	f.asked = append(f.asked, strings.TrimSuffix(q.Name, ".")+" "+dns.TypeToString[q.Qtype])
	r := new(dns.Msg)
	r.SetReply(m)
	name := strings.TrimSuffix(q.Name, ".")
	switch {
	case f.bad:
		r.Rcode = dns.RcodeServerFailure
	case slices.Contains(f.zones, name) && q.Qtype == dns.TypeSOA:
		r.Authoritative = true
		rr, _ := dns.NewRR(q.Name + " 300 IN SOA ns1. admin. 1 3600 900 604800 300")
		r.Answer = append(r.Answer, rr)
	case strings.HasSuffix(name, ".invalid"):
		r.Rcode = dns.RcodeNameError
	case q.Qtype == dns.TypeSOA:
		r.Rcode = dns.RcodeRefused // not a zone of its own
	default:
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A: net.IPv4(192, 0, 2, 7)})
	}
	w.WriteMsg(r)
}

func (f *fakeResolver) askedFor(q string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.asked, q)
}

// A single adopted node with a DNS peer that answers is rebooted without AllowSingle; the
// peer is asked for the node's zones (its secondaries) and a forwarded name.
func TestRolloutSingleNodeDNSPeer(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	a.rebootNeeded = true
	tech := newResolver(t, "home.example")
	p := fastPlan(a.host)
	p.DNSPeers = []DNSPeer{{Addr: tech.addr}}
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err != nil {
		t.Fatal(err)
	}
	want := []string{"push blocklist", "push control", "reboot command 040000000001", "down", "up"}
	if got := w.eventsOf(a.host); !slices.Equal(got, want) {
		t.Fatal(got)
	}
	if !tech.askedFor("home.example SOA") || !tech.askedFor("example.com A") {
		t.Fatal("peer not checked:", tech.asked)
	}
}

// A DNS peer that fails its checks doesn't count: with no other node, the change is
// refused as the last healthy node.
func TestRolloutDNSPeerFails(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	tech := newResolver(t, "home.example")
	tech.broken(true)
	p := fastPlan(a.host)
	p.DNSPeers = []DNSPeer{{Addr: tech.addr}}
	_, err := w.client().Rollout(context.Background(), p, blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "last healthy node") || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
	// Not authoritative for the zone the node serves: as bad as no answer.
	tech2 := newResolver(t, "other.example")
	p.DNSPeers = []DNSPeer{{Addr: tech2.addr}}
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err == nil || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
	// Zones named for the peer replace the node's.
	p.DNSPeers = []DNSPeer{{Addr: tech2.addr, Zones: []string{"other.example"}}}
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err != nil {
		t.Fatal(err)
	}
}

// The peer is checked again right before the reboot: one that stopped answering during
// the push stops it there.
func TestRolloutDNSPeerRegated(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	a.rebootNeeded = true
	tech := newResolver(t, "home.example")
	a.afterPush = func() { tech.broken(true) }
	p := fastPlan(a.host)
	p.DNSPeers = []DNSPeer{{Addr: tech.addr}}
	_, err := w.client().Rollout(context.Background(), p, blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "not rebooted") || !strings.Contains(err.Error(), "DNS peer") {
		t.Fatal(err)
	}
	if got := w.eventsOf(a.host); !slices.Equal(got, []string{"push blocklist"}) {
		t.Fatal(got)
	}
}

// A coordinated reboot of the only node, with a DNS peer; refused once the peer fails.
func TestRebootDNSPeer(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	tech := newResolver(t, "home.example")
	p := fastPlan()
	p.DNSPeers = []DNSPeer{{Addr: tech.addr}}
	c := w.client()
	if err := c.Reboot(context.Background(), p, a.host, false); err != nil {
		t.Fatal(err)
	}
	if got := w.eventsOf(a.host); !slices.Equal(got, []string{"push control", "reboot command 040000000000", "down", "up"}) {
		t.Fatal(got)
	}
	tech.broken(true)
	err := c.Reboot(context.Background(), p, a.host, false)
	if err == nil || errors.Is(err, ErrSingle) || !strings.Contains(err.Error(), "last healthy node") {
		t.Fatal(err)
	}
	// A peer node and a DNS peer, both answering.
	b := w.node(true)
	p.Peers = []string{b.host}
	tech.broken(false)
	if err := c.Reboot(context.Background(), p, a.host, false); err != nil {
		t.Fatal(err)
	}
}

// The node being changed, named as a DNS peer (its address, DNS port 53), never counts
// for itself: it would pass the checks right up to its reboot.
func TestDNSPeerIsTheNode(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	ip, _, _ := net.SplitHostPort(a.host)
	for _, addr := range []string{ip, net.JoinHostPort(ip, "53")} {
		p := fastPlan()
		p.DNSPeers = []DNSPeer{{Addr: addr}}
		err := w.client().Reboot(context.Background(), p, a.host, false)
		if err == nil || !strings.Contains(err.Error(), "being changed") || len(w.eventsOf(a.host)) != 0 {
			t.Fatal(addr, err, w.eventsOf(a.host))
		}
	}
}
