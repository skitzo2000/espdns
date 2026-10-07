package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

func blocklistChange() Change {
	return Change{Kind: release.Blocklist, Payload: func(context.Context, string, release.NodeStatus) ([]byte, error) {
		return []byte("list"), nil
	}}
}

func fastPlan(targets ...string) Plan {
	return Plan{Targets: targets, Soak: 5 * time.Millisecond, RebootWait: 5 * time.Second, ConfirmWait: 300 * time.Millisecond,
		Checks: Checks{Forwarded: []string{"example.com"}, Blocked: []string{"ads.example"}}}
}

// The canary goes first, then the rest in order, one at a time, each checked.
func TestRolloutOrder(t *testing.T) {
	w := newWorld(t)
	a, b, c := w.node(true), w.node(true), w.node(true)
	p := fastPlan(a.host, b.host, c.host)
	p.Canary = c.host
	res, err := w.client().Rollout(context.Background(), p, blocklistChange())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{c.host + " blocklist", a.host + " blocklist", b.host + " blocklist"}
	if got := w.pushes(); !slices.Equal(got, want) {
		t.Fatalf("pushes %v, want %v", got, want)
	}
	if !slices.Equal(res.Done, []string{c.host, a.host, b.host}) || res.Failed != "" {
		t.Fatalf("%+v", res)
	}
}

// Progress only listens: a listener that panics changes nothing about the rollout, each
// node still pushed, rebooted and checked, and it hears every step.
func TestRolloutProgressOnlyListens(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	c := w.client()
	var mu sync.Mutex
	var steps []string
	c.Progress = func(host string, s Step, detail string) {
		mu.Lock()
		steps = append(steps, string(s))
		mu.Unlock()
		panic("a listener's bug")
	}
	res, err := c.Rollout(context.Background(), fastPlan(a.host, b.host), firmwareChange(t, "00000000000000aa"))
	if err != nil || len(res.Done) != 2 || a.elf != "00000000000000aa" || b.elf != "00000000000000aa" {
		t.Fatal(res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range []Step{StepGate, StepPushing, StepRebooting, StepChecking, StepChecked, StepSoaking, StepDone} {
		if !slices.Contains(steps, string(s)) {
			t.Errorf("never heard %s: %v", s, steps)
		}
	}
}

// No node is changed while it is the last one answering, whatever the plan says.
func TestRolloutKeepsLastHealthyNode(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	b.state, b.reasons = "fault", []string{"listeners failed"}
	p := fastPlan(a.host)
	p.Peers, p.Force, p.AllowSingle = []string{b.host}, true, true
	res, err := w.client().Rollout(context.Background(), p, blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "last healthy node") || res.Failed != a.host {
		t.Fatalf("%+v %v", res, err)
	}
	if len(w.pushes()) != 0 {
		t.Fatalf("pushed: %v", w.pushes())
	}

	// A degraded peer still answers: a live change goes on, one that may reboot needs force.
	b.state, b.reasons = "degraded", []string{"sd card"}
	p.Force = false
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err == nil ||
		!strings.Contains(err.Error(), "unhealthy") {
		t.Fatal(err)
	}
	p.Force = true
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err != nil {
		t.Fatal(err)
	}
}

// A single node needs AllowSingle, and the error says so.
func TestRolloutSingleNode(t *testing.T) {
	w := newWorld(t)
	a := w.node(true)
	_, err := w.client().Rollout(context.Background(), fastPlan(a.host), blocklistChange())
	if !errors.Is(err, ErrSingle) || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
	p := fastPlan(a.host)
	p.AllowSingle = true
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); err != nil {
		t.Fatal(err)
	}
}

// A release that waits for a reboot gets one from the controller, and the next node starts
// only once the first is back: never two down at once.
func TestRolloutRebootPending(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	a.rebootNeeded, b.rebootNeeded = true, true
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), blocklistChange())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []*fakeNode{a, b} {
		got := w.eventsOf(n.host)
		want := []string{"push blocklist", "push control", "reboot command 040000000001", "down", "up"}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", n.host, got, want)
		}
	}
	if w.maxDn != 1 || len(res.Done) != 2 {
		t.Fatalf("%d down at once; %+v", w.maxDn, res)
	}
	// Firmware that reboots by itself: waited for, no reboot command.
	w2 := newWorld(t)
	c, d := w2.node(false), w2.node(false)
	c.rebootNeeded, d.rebootNeeded = true, true
	if _, err := w2.client().Rollout(context.Background(), fastPlan(c.host, d.host), blocklistChange()); err != nil {
		t.Fatal(err)
	}
	if got := w2.eventsOf(c.host); !slices.Equal(got, []string{"push blocklist", "down", "up"}) {
		t.Fatal(got)
	}
}

// The first node that fails its checks stops the push; the rest are left alone. A list goes
// back to the copy each had on every node that took it, the failed node first.
func TestRolloutStopsOnFailure(t *testing.T) {
	w := newWorld(t)
	a, b, c := w.node(true), w.node(true), w.node(true)
	b.afterPush = func() { b.notBlocking = true }
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host, c.host), blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "ads.example: not blocked") {
		t.Fatal(err)
	}
	if res.Failed != b.host || len(res.Done) != 0 || !slices.Equal(res.Reverted, []string{b.host, a.host}) ||
		!slices.Equal(res.Left, []string{c.host}) || len(res.NotReverted) != 0 {
		t.Fatalf("%+v", res)
	}
	for _, n := range []*fakeNode{a, b} {
		if n.blocklist.Seq != 1 {
			t.Errorf("%s runs blocklist seq %d, not the one it had", n.host, n.blocklist.Seq)
		}
	}
	if len(w.eventsOf(c.host)) != 0 {
		t.Fatal("touched the third node")
	}

	// A new degraded reason fails it too; one it had before doesn't.
	w2 := newWorld(t)
	d, e := w2.node(true), w2.node(true)
	d.state, d.reasons = "degraded", []string{"sd card"}
	if _, err := w2.client().Rollout(context.Background(), fastPlan(d.host), Change{Kind: release.Blocklist,
		Payload: blocklistChange().Payload}); err == nil {
		t.Fatal("single node accepted")
	}
	p := fastPlan(d.host)
	p.Peers, p.Checks = []string{e.host}, Checks{Off: true}
	if _, err := w2.client().Rollout(context.Background(), p, blocklistChange()); err != nil {
		t.Fatal(err)
	}
	d.afterPush = func() { d.reasons = append(d.reasons, "blocking") }
	if _, err := w2.client().Rollout(context.Background(), p, blocklistChange()); err == nil ||
		!strings.Contains(err.Error(), "degraded: blocking") {
		t.Fatal(err)
	}
}

// A node with the service off in its config refuses the release: the rollout stops before
// any node is touched. With forwarding off, the checks of forwarded and blocked names, which
// it answers REFUSED, are skipped.
func TestRolloutServiceOff(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	b.services = map[string]string{"dns": "running", "forwarding": "running", "hosted": "running", "blocking": "off"}
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "blocking is off in its node config") {
		t.Fatal(err)
	}
	if len(w.pushes()) != 0 || !slices.Equal(res.Left, []string{a.host, b.host}) {
		t.Fatalf("pushes %v, result %+v", w.pushes(), res)
	}
	zones := Change{Kind: release.Zones, Payload: blocklistChange().Payload}
	b.services["blocking"], b.services["hosted"] = "running", "off"
	if _, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), zones); err == nil ||
		!strings.Contains(err.Error(), "hosted is off") {
		t.Fatal(err)
	}
	// Overrides go to a node with blocking on and forwarding off; its checks pass.
	b.services["hosted"], b.services["forwarding"] = "running", "off"
	if _, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host),
		Change{Kind: release.Overrides, Payload: blocklistChange().Payload}); err != nil {
		t.Fatal(err)
	}
	if len(w.pushes()) != 2 {
		t.Fatal(w.pushes())
	}
	// Reported on, forwarding is checked: a node that answers REFUSED fails.
	h := Health{Blocklist: &Stored{State: "on", Seq: 1}}
	ch := fastPlan().Checks
	ch.MustResolve = []string{"example.org"}
	off := release.NodeStatus{Services: []release.ServiceStatus{{Name: "forwarding", State: "off"}}}
	if err := w.client().CheckDNS(context.Background(), b.host, off, h, ch); err != nil {
		t.Fatal(err)
	}
	err = w.client().CheckDNS(context.Background(), b.host, release.NodeStatus{}, h, ch)
	for _, want := range []string{"forwarded example.com: REFUSED", "must-resolve example.org: REFUSED", "blocked ads.example: not blocked"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want %q: %v", want, err)
		}
	}
}

func firmwareChange(t *testing.T, elf string) Change {
	img := app(t, elf)
	d, err := release.ParseAppDesc(img)
	if err != nil {
		t.Fatal(err)
	}
	return Change{Kind: release.Firmware, Firmware: []Firmware{{Image: "esp32p4-rev1", App: img, Desc: d}}}
}

// Firmware is staged, the node rebooted into it by the controller, and done once the new
// build confirms itself (trial, then valid).
func TestRolloutFirmware(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(false)
	b.image = "esp32s3-octal"
	ch := firmwareChange(t, "00000000000000aa")
	if _, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch); err == nil ||
		!strings.Contains(err.Error(), "esp32s3-octal") || len(w.pushes()) != 0 {
		t.Fatal("a node with no image for its chip wasn't refused before any push:", err)
	}
	b.image = "esp32p4-rev1"
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch)
	if err != nil {
		t.Fatal(err)
	}
	if got := w.eventsOf(a.host); !slices.Equal(got, []string{"push firmware", "push control", "reboot command 040000000001", "down", "up"}) {
		t.Fatal(got)
	}
	if got := w.eventsOf(b.host); !slices.Equal(got, []string{"push firmware", "down", "up"}) {
		t.Fatal(got)
	}
	if a.elf != "00000000000000aa" || a.otaState != "valid" || b.elf != "00000000000000aa" || len(res.Done) != 2 {
		t.Fatalf("%s %s %s %+v", a.elf, a.otaState, b.elf, res)
	}
	// Again: both already run it.
	res, err = w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch)
	if err != nil || len(res.Skipped) != 2 {
		t.Fatal(res, err)
	}
	// Reinstalled: the same build back is no rollback.
	ch.Reinstall = true
	res, err = w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch)
	if err != nil || len(res.Done) != 2 || a.slot != "ota_0" { // ota_1, then back to ota_0
		t.Fatal(res, err, a.slot)
	}
	// A reinstall that rolls back comes back on the same build, but on the old slot.
	a.rollback = true
	res, err = w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch)
	if err == nil || !strings.Contains(err.Error(), "rolled back") || res.Failed != a.host {
		t.Fatal(res, err)
	}
}

// After the reboot the checks wait while a service is still starting: a list loaded after
// them would flush the cache their queries filled, and blocked names would go unchecked.
func TestRolloutWaitsForServices(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	a.services = map[string]string{"dns": "running", "forwarding": "running", "blocking": "running"}
	a.startPolls = 5
	if _, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), firmwareChange(t, "00000000000000cc")); err != nil {
		t.Fatal(err)
	}
	if !a.wasStarting || a.queriedEarly != 0 || a.services["blocking"] != "running" {
		t.Fatalf("starting seen %v, %d queries while starting", a.wasStarting, a.queriedEarly)
	}
	// Never done starting: not in service.
	a.startPolls = 1 << 30
	_, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), firmwareChange(t, "00000000000000dd"))
	if err == nil || !strings.Contains(err.Error(), "still starting: blocking") || a.queriedEarly != 0 {
		t.Fatal(err, a.queriedEarly)
	}
}

// A build that rolls back is reported, and the push stops there.
func TestRolloutFirmwareRollback(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	a.rollback = true
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), firmwareChange(t, "00000000000000bb"))
	if err == nil || !strings.Contains(err.Error(), "rolled back") || res.Failed != a.host || len(w.eventsOf(b.host)) != 0 {
		t.Fatal(res, err)
	}
}

// A coordinated reboot: only with another node answering, and only once.
func TestReboot(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	p := fastPlan()
	p.Peers = []string{b.host}
	c := w.client()
	if err := c.Reboot(context.Background(), p, a.host, true); err != nil {
		t.Fatal(err)
	}
	if len(w.eventsOf(a.host)) != 0 {
		t.Fatal("rebooted with nothing pending")
	}
	if err := c.Reboot(context.Background(), p, a.host, false); err != nil {
		t.Fatal(err)
	}
	if got := w.eventsOf(a.host); !slices.Equal(got, []string{"push control", "reboot command 040000000000", "down", "up"}) {
		t.Fatal(got)
	}
	b.state = "no network"
	if err := c.Reboot(context.Background(), p, a.host, false); err == nil {
		t.Fatal("rebooted the last answering node")
	}
	old := w.node(false)
	if err := c.Reboot(context.Background(), p, old.host, false); err == nil || !strings.Contains(err.Error(), "before the reboot command") {
		t.Fatal(err)
	}
}

// A node coming back on a new address: down at first, then on trial until it is queried,
// then confirmed. Another node on the address it had is never taken for it.
func TestConfirmConfig(t *testing.T) {
	w := newWorld(t)
	n, other := w.node(true), w.node(true)
	var mu sync.Mutex
	polls, queried := 0, false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if polls++; polls == 1 {
			http.Error(rw, "rebooting", http.StatusServiceUnavailable)
			return
		}
		w.mu.Lock()
		queried = len(w.eventsOf2(n.host)) > 0
		w.mu.Unlock()
		rw.Write([]byte(`{"node_id":"aa:bb:cc:00:00:01","config":{"source":"node","seq":42,"address":"static","trial":` +
			map[bool]string{true: "false", false: "true"}[queried] + `}}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := w.client()
	c.DNS = recorder{w, n.host, host}
	locate := func(context.Context) []string { return []string{other.host, host} }
	st, at, err := c.ConfirmConfig(context.Background(), locate, "AA:BB:CC:00:00:01", 42, 5*time.Second)
	if err != nil || st.Seq != 42 || st.Trial || at != host {
		t.Fatalf("%+v %s %v", st, at, err)
	}
	if _, _, err := c.ConfirmConfig(context.Background(), locate, "", 43, 50*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "previous config") {
		t.Fatal(err)
	}
}

// recorder answers DNS for the host the config waits on, recording that it was queried.
type recorder struct {
	w         *world
	as, alias string
}

func (r recorder) Exchange(ctx context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	if host != r.alias {
		return nil, errors.New("queried the wrong host")
	}
	r.w.mu.Lock()
	r.w.event(r.as, "queried")
	r.w.mu.Unlock()
	return r.w.Exchange(ctx, r.as, m)
}

func (w *world) eventsOf2(host string) []string {
	var out []string
	for _, e := range w.events {
		if h, _, _ := strings.Cut(e, ": "); h == host {
			out = append(out, e)
		}
	}
	return out
}

// Adoption: a dry run checks and says, and pushes nothing; a config on DHCP stops without
// the reservation, before any change.
func TestAdoptDryRun(t *testing.T) {
	w := newWorld(t)
	n := w.node(true)
	n.unadopted, n.addr = true, "192.0.2.252/23"
	var sets []url.Values
	var gets int
	tech := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("token") != "tok" {
			rw.Write([]byte(`{"status":"invalid-token","errorMessage":"bad token"}`))
			return
		}
		switch r.URL.Path {
		case "/api/zones/options/get":
			gets++
			rw.Write([]byte(`{"status":"ok","response":{"name":"` + r.Form.Get("zone") + `","zoneTransfer":"AllowOnlySpecifiedNameServers",` +
				`"zoneTransferNameServers":["192.0.2.253"],"notify":"SpecifiedNameServers","notifyNameServers":["192.0.2.253"]}}`))
		case "/api/zones/options/set":
			sets = append(sets, r.Form)
			rw.Write([]byte(`{"status":"ok","response":{}}`))
		}
	}))
	defer tech.Close()
	zones := []string{"home.example"}
	cfg := &nodecfg.Config{Secondary: &nodecfg.Secondary{Primary: "192.0.2.254", Zones: &zones}}
	a := Adopt{Host: n.host, ID: n.id, Address: netip.MustParsePrefix("192.0.2.252/23"),
		Gateway: netip.MustParseAddr("192.0.2.1"), Config: cfg, DryRun: true,
		Primary: &primary.Technitium{URL: tech.URL, Token: "tok", HTTP: tech.Client(), DryRun: true}}
	c := w.client()
	var logs []string
	c.Logf = func(f string, args ...any) { logs = append(logs, f) }
	a.Primary.(*primary.Technitium).Logf = c.Logf
	if err := c.Adopt(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if len(w.pushes()) != 0 || len(sets) != 0 || gets != 1 {
		t.Fatalf("dry run changed something: %v, %d sets, %d gets", w.pushes(), len(sets), gets)
	}
	if slices.ContainsFunc(logs, func(s string) bool { return strings.Contains(s, "reserve") }) {
		t.Fatal("a static address asked for a reservation:", logs)
	}
	// A config on DHCP (another network) needs the reservation first.
	a.DryRun, a.Primary.(*primary.Technitium).DryRun = false, false
	a.Address, a.Gateway, a.DHCP = netip.Prefix{}, netip.Addr{}, true
	if err := c.Adopt(context.Background(), a); !errors.Is(err, ErrReservation) || len(w.pushes()) != 0 || len(sets) != 0 {
		t.Fatal(err, w.pushes(), sets)
	}
	a.ID = "aa:bb:cc:dd:ee:ff"
	a.Reserved = true
	if err := c.Adopt(context.Background(), a); err == nil || !strings.Contains(err.Error(), "not aa:bb:cc:dd:ee:ff") {
		t.Fatal(err)
	}
}

// Adoption without a lease: the node is on the address it was flashed with, and adopt
// keeps it (address and gateway from its /status) unless given another; a node that
// reports no static address needs one given.
func TestAdoptAddress(t *testing.T) {
	w := newWorld(t)
	n := w.node(true)
	n.unadopted, n.addr = true, "192.0.2.252/23"
	c := w.client()
	var logs []string
	c.Logf = func(f string, args ...any) { logs = append(logs, fmt.Sprintf(f, args...)) }
	a := Adopt{Host: n.host, ID: n.id, DryRun: true}
	if err := c.Adopt(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(logs, "\n")
	if !strings.Contains(all, "static address 192.0.2.252/23, gateway 192.0.2.1 (kept, from its board)") ||
		!strings.Contains(all, `"network":{"address":"192.0.2.252/23","gateway":"192.0.2.1"}`) ||
		strings.Contains(all, "reserve") || len(w.pushes()) != 0 {
		t.Fatal(all)
	}
	// A new address in the same network keeps the node's gateway.
	logs = nil
	a.Address = netip.MustParsePrefix("192.0.2.60/23")
	if err := c.Adopt(context.Background(), a); err != nil || !strings.Contains(strings.Join(logs, "\n"), "gateway 192.0.2.1 (new)") {
		t.Fatal(err, logs)
	}
	// In another network it needs its own.
	a.Address = netip.MustParsePrefix("198.51.100.60/24")
	if err := c.Adopt(context.Background(), a); err == nil || !strings.Contains(err.Error(), "need the gateway") {
		t.Fatal(err)
	}
	a.Gateway = netip.MustParseAddr("198.51.100.1")
	if err := c.Adopt(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	a.DHCP = true
	if err := c.Adopt(context.Background(), a); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatal(err)
	}
	// No static address to keep: give one.
	n.addr = ""
	if err := c.Adopt(context.Background(), Adopt{Host: n.host, DryRun: true}); err == nil ||
		!strings.Contains(err.Error(), "no static address") {
		t.Fatal(err)
	}
}

// stubDNS answers for the hosts in it and times out for the rest.
type stubDNS map[string]bool

func (s stubDNS) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	if !s[host] {
		return nil, errors.New("timeout")
	}
	r := new(dns.Msg)
	r.SetRcode(m, dns.RcodeNameError)
	return r, nil
}

// Before a node moves onto an address, nothing else may be there: with no DHCP server, an
// address given by hand twice is the collision to catch. Another node, any other web
// server, a host that refuses the connection and a DNS server all count; the node itself
// and silence don't.
func TestAdoptAddressInUse(t *testing.T) {
	w := newWorld(t)
	n, other := w.node(true), w.node(true)
	n.unadopted, n.addr = true, "192.0.2.252/23"
	web := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(web.Close)
	at := map[string]string{"203.0.113.1:80": other.host, "203.0.113.2:80": web.Listener.Addr().String(), "203.0.113.6:80": n.host}
	c := w.client()
	c.HTTP = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if to, ok := at[addr]; ok {
				addr = to
			}
			switch {
			case addr == "203.0.113.3:80":
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
			case !strings.HasPrefix(addr, "127.0.0.1:"):
				return nil, errors.New("test: no route")
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	c.DNS = stubDNS{"203.0.113.4": true, n.host: true, other.host: true}
	// The ARP table: 203.0.113.7 answered (a host that drops HTTP and DNS), 203.0.113.8 didn't,
	// 203.0.113.9 is the node itself (its interface's MAC, from an earlier address).
	arp := filepath.Join(t.TempDir(), "arp")
	os.WriteFile(arp, []byte("IP address       HW type     Flags       HW address            Mask     Device\n"+
		"203.0.113.7         0x1         0x2         aa:bb:cc:00:00:07     *        eth0\n"+
		"203.0.113.8         0x1         0x0         00:00:00:00:00:00     *        eth0\n"+
		"203.0.113.9         0x1         0x2         02:00:00:00:00:99     *        eth0\n"), 0o600)
	old := arpTable
	arpTable = arp
	t.Cleanup(func() { arpTable = old })
	ctx := context.Background()
	for addr, want := range map[string]string{
		"203.0.113.1": "in use by node " + other.id,
		"203.0.113.2": "answers HTTP",
		"203.0.113.3": "refuses connections",
		"203.0.113.4": "a DNS server answers",
		"203.0.113.5": "",
		"203.0.113.6": "",
		"203.0.113.7": "answers ARP",
		"203.0.113.8": "",
		"203.0.113.9": "",
	} {
		err := c.AddressFree(ctx, addr, n.id, "02:00:00:00:00:99")
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("%s: %v, want %q", addr, err, want)
		}
	}
	// Adopt stops there, before any change.
	a := Adopt{Host: n.host, ID: n.id, Address: netip.MustParsePrefix("203.0.113.2/24"), Gateway: netip.MustParseAddr("203.0.113.254")}
	if err := c.Adopt(ctx, a); err == nil || !strings.Contains(err.Error(), "3. 203.0.113.2 is in use") || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
}

// Firmware from before /health: its health comes from /status.
func TestHealthLegacy(t *testing.T) {
	w := newWorld(t)
	n := w.node(false)
	h, err := w.client().Health(context.Background(), n.host)
	if err != nil || !h.Legacy || h.State != "healthy" || h.InService(nil) != nil {
		t.Fatal(h, err)
	}
}

// A node already adopted is in service: adopt moves it only under the rule, and checks
// the rule again right before it reboots it.
func TestAdoptInService(t *testing.T) {
	w := newWorld(t)
	n, peer := w.node(true), w.node(true)
	a := Adopt{Host: n.host, ID: n.id, Address: netip.MustParsePrefix("192.0.2.99/24"),
		Gateway: netip.MustParseAddr("192.0.2.1"), ConfirmWait: 300 * time.Millisecond}
	c := w.client()
	if err := c.Adopt(context.Background(), a); !errors.Is(err, ErrSingle) || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
	a.Peers = []string{peer.host}
	n.pending = []string{"config: address"} // the config waits for a reboot
	n.afterPush = func() { peer.state = "fault" }
	if err := c.Adopt(context.Background(), a); err == nil || !strings.Contains(err.Error(), "not rebooted") {
		t.Fatal(err)
	}
	if got := w.eventsOf(n.host); !slices.Equal(got, []string{"push config"}) {
		t.Fatal("rebooted with the other node down:", got)
	}
}

// The rule is checked again right before a node that waits for a reboot is rebooted:
// another node that went down during the push stops it there.
func TestRolloutRegatesBeforeReboot(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	a.rebootNeeded = true
	a.afterPush = func() { b.state = "no network" }
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), blocklistChange())
	if err == nil || !strings.Contains(err.Error(), "not rebooted") || res.Failed != a.host {
		t.Fatal(res, err)
	}
	if got := w.eventsOf(a.host); !slices.Equal(got, []string{"push blocklist"}) || w.maxDn != 0 {
		t.Fatal(got, w.maxDn)
	}
}

// A target clients don't use (not adopted) doesn't count as answering for another.
func TestRolloutUncounted(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	p := fastPlan(a.host, b.host)
	p.Uncounted = []string{b.host}
	if _, err := w.client().Rollout(context.Background(), p, blocklistChange()); !errors.Is(err, ErrSingle) || len(w.pushes()) != 0 {
		t.Fatal(err, w.pushes())
	}
}

// A /status that fails once while the node stays up isn't a reboot.
func TestWaitRebootBlip(t *testing.T) {
	w := newWorld(t)
	n := w.node(true)
	c := w.client()
	before, err := c.Status(context.Background(), n.host)
	if err != nil {
		t.Fatal(err)
	}
	n.blips = 1
	p := fastPlan()
	p.RebootWait = 200 * time.Millisecond
	if err := c.waitReboot(context.Background(), p, n.host, before); err == nil {
		t.Fatal("a failed /status taken for a reboot")
	}
	w.mu.Lock()
	n.reboot()
	w.mu.Unlock()
	if err := c.waitReboot(context.Background(), p, n.host, before); err != nil {
		t.Fatal(err)
	}
}

// Stop ends a rollout at the next safe point: closed before the start, nothing is touched;
// closed during the canary's soak, the canary is done and the next node isn't started.
func TestRolloutStop(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	stop := make(chan struct{})
	close(stop)
	p := fastPlan(a.host, b.host)
	p.Stop = stop
	res, err := w.client().Rollout(context.Background(), p, blocklistChange())
	if !errors.Is(err, ErrStopped) || len(w.pushes()) != 0 || !slices.Equal(res.Left, []string{a.host, b.host}) {
		t.Fatalf("%+v %v %v", res, err, w.pushes())
	}

	stop = make(chan struct{})
	p = fastPlan(a.host, b.host)
	p.Soak, p.Stop = time.Minute, stop
	c := w.client()
	c.Logf = func(f string, args ...any) {
		if strings.HasSuffix(f, "soaking %v") {
			close(stop)
		}
	}
	res, err = c.Rollout(context.Background(), p, blocklistChange())
	if !errors.Is(err, ErrStopped) || !slices.Equal(res.Done, []string{a.host}) || res.Failed != "" ||
		!slices.Equal(res.Left, []string{b.host}) || !slices.Equal(w.pushes(), []string{a.host + " blocklist"}) {
		t.Fatalf("%+v %v %v", res, err, w.pushes())
	}
}

// Firmware that would leave a node with no address, or another, where its address depends
// on the one built into its firmware, is refused before any push.
func TestFirmwareAddressCheck(t *testing.T) {
	marked := func(addr string) []byte {
		return append(app(t, "00000000000000aa"), "espdns:builtin-address="+addr+"\x00"...)
	}
	st := func(from, boardSource string) release.NodeStatus {
		return release.NodeStatus{Board: "p4-ip101", BoardSource: boardSource,
			Config: &release.ConfigStatus{AddressFrom: from, IP: "192.0.2.53/24"}}
	}
	for _, c := range []struct {
		st     release.NodeStatus
		app    []byte
		refuse string
	}{
		{st("firmware", "fallback"), marked("192.0.2.53"), ""},
		{st("firmware", "fallback"), marked(""), "built into the firmware it runs"},
		{st("firmware", "fallback"), marked("192.0.2.99"), "has 192.0.2.99 built in"},
		{st("config", "fallback"), marked(""), "no board partition"},
		{st("config", ""), marked(""), "no board partition"},
		{st("config", "fallback"), marked(netip.AddrFrom4([4]byte{10, 0, 0, 40}).String()), ""}, // a config that moved it: its fallback stays the old one
		{st("config", "fallback"), marked("192.0.2.40"), "a documentation"},                     // CI's, or an example's
		{st("config", "fallback"), marked("192.0.2.53"), ""},                                    // its own
		{st("config", "partition"), marked(""), ""},                                             // the board partition's address is the fallback
		{st("board", "partition"), marked(""), ""},
		{st("firmware", "fallback"), app(t, "00000000000000aa"), ""}, // an image from before the marker: not known
		{release.NodeStatus{}, marked(""), ""},                       // firmware from before address_from
	} {
		err := FirmwareAddressCheck("n", c.st, c.app)
		if c.refuse == "" && err != nil || c.refuse != "" && (err == nil || !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%+v %q: %v", c.st.Config, c.app[1024:], err)
		}
	}
	// In a rollout, before any node is touched
	w := newWorld(t)
	a := w.node(true)
	ch := firmwareChange(t, "00000000000000aa")
	ch.Firmware[0].App = append(ch.Firmware[0].App, "espdns:builtin-address=\x00"...)
	st0, err := w.client().Status(context.Background(), a.host)
	if err != nil {
		t.Fatal(err)
	}
	st0.Config = &release.ConfigStatus{AddressFrom: "firmware", IP: a.host + "/24"}
	if _, _, err := ch.Prepare(context.Background(), a.host, st0); err == nil {
		t.Fatal("firmware without the node's built-in address was not refused")
	}
}
