package adoption

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/faketech"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

const token = "0123456789abcdef-test-token"

// env is a fake network: an adopted node in settings.json (203.0.113.51), a node to adopt
// (203.0.113.52, unadopted, on its board's address), a web server on 203.0.113.99, a fake
// Technitium with the zones the config carries, and a data directory.
type env struct {
	t    *testing.T
	dir  string
	lan  *fakenode.Lan
	peer *fakenode.Node
	node *fakenode.Node
	tech *faketech.Server
	turl string
	tpin string // its certificate's fingerprint, pinned
	key  *ecdsa.PrivateKey
	logs []string
	mu   sync.Mutex
}

func newEnv(t *testing.T) *env {
	e := &env{t: t, dir: t.TempDir(), lan: fakenode.NewLan()}
	t.Cleanup(e.lan.Close)
	e.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(name string, last byte, unadopted bool) *fakenode.Node {
		n := fakenode.New(name, [6]byte{2, 0, 0, 0, 0, last}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(e.key))
		n.Addr, n.Gateway, n.Unadopted, n.DownFor = fmt.Sprintf("203.0.113.%d", last), "203.0.113.1", unadopted, 20*time.Millisecond
		e.lan.Add(n)
		return n
	}
	e.peer, e.node = mk("dns1", 51, false), mk("new", 52, true)
	if _, err := pins.Open(e.dir).Pin(e.peer.ID(), "203.0.113.51"); err != nil { // adopted before
		t.Fatal(err)
	}
	e.lan.Other("203.0.113.99", http.NotFoundHandler())
	e.tech = faketech.New(token, "home.example", "lab.example")
	ts := httptest.NewTLSServer(e.tech) // its own certificate, pinned below
	t.Cleanup(ts.Close)
	e.turl, e.tpin = ts.URL, primary.Fingerprint(ts.Certificate())
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"}, Primary: &primary.Config{Kind: "technitium", URL: e.turl,
		CertSHA256: e.tpin}}); err != nil {
		t.Fatal(err)
	}
	e.config("n2.json", `{"name": "dns2", "forwarders": ["9.9.9.9"], "secondary": {"primary": "203.0.113.254", "zones": ["home.example", "lab.example"]}}`)
	return e
}

func (e *env) config(name, text string) {
	p := filepath.Join(configs.Path(e.dir), name)
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) logf(f string, a ...any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logs = append(e.logs, fmt.Sprintf(f, a...))
}

func (e *env) log() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.logs, "\n")
}

func (e *env) client() *fleet.Client {
	hc := e.lan.HTTP()
	return &fleet.Client{HTTP: hc, DNS: e.lan, PeerDNS: e.lan, Poll: 10 * time.Millisecond, Logf: e.logf,
		Pusher: &release.Pusher{Key: e.key, KeyID: release.KeyRelease, Pins: pins.Open(e.dir), Client: hc}}
}

func (e *env) req(r Request) Request {
	r.DataDir, r.Wait = e.dir, 5*time.Second
	if r.Host == "" {
		r.Host = "203.0.113.52"
	}
	if r.Config == "" {
		r.Config = "n2.json"
	}
	return r
}

func tok(t string) Token { return func() (string, error) { return t, nil } }

func (e *env) adopt(r Request, t Token) (Result, error) {
	ctx := context.Background()
	c := e.client()
	b, err := Build(ctx, c, e.req(r), t, e.logf)
	if err != nil {
		return Result{}, err
	}
	return Run(ctx, c, b, "test", e.logf)
}

func (e *env) pushes(n *fakenode.Node) []string {
	return slices.DeleteFunc(n.Events(), func(s string) bool { return !strings.HasPrefix(s, "push config") })
}

// A node adopted onto a new static address: the zone primary allows it for each zone
// first, the config goes to where it is, it reboots onto the address, is confirmed there,
// the config it runs is recorded and its address added to settings.json.
func TestAdoptNewAddress(t *testing.T) {
	e := newEnv(t)
	// The dry run: Technitium read, nothing changed anywhere.
	r, err := e.adopt(Request{Address: "203.0.113.60/24", DryRun: true}, tok(token))
	if err != nil {
		t.Fatal(err, e.log())
	}
	if len(e.tech.Sets()) != 0 || len(e.pushes(e.node)) != 0 || r.Seq != 0 {
		t.Fatal("the dry run changed something", e.tech.Sets(), e.node.Events())
	}
	if _, err := pins.Open(e.dir).Seq(e.node.ID(), "config"); !errors.Is(err, pins.ErrNotPinned) {
		t.Fatal("the dry run pinned the node:", err)
	}
	if !strings.Contains(e.log(), "technitium: home.example: would set zone transfer name servers 203.0.113.60") {
		t.Fatal(e.log())
	}
	r, err = e.adopt(Request{Address: "203.0.113.60/24", AddToSettings: true}, tok(token))
	if err != nil {
		t.Fatal(err, e.log())
	}
	for _, z := range []string{"home.example", "lab.example"} {
		zo, _ := e.tech.Zone(z)
		if !slices.Equal(zo.TransferList, []string{"203.0.113.60"}) || !slices.Equal(zo.NotifyList, []string{"203.0.113.60"}) ||
			zo.Transfer != "AllowBothZoneAndSpecifiedNameServers" || zo.Notify != "BothZoneAndSpecifiedNameServers" {
			t.Errorf("%s: %+v", z, zo)
		}
	}
	if ev := e.node.Events(); !slices.Contains(ev, "moved to 203.0.113.60") || len(e.pushes(e.node)) != 1 {
		t.Fatal(ev)
	}
	if r.Addr != "203.0.113.60" || r.NodeID != e.node.ID() || !r.Recorded || !r.AddedToSettings {
		t.Fatalf("%+v", r)
	}
	p, err := configs.LoadPushed(e.dir, e.node.ID())
	if err != nil || p == nil || p.File != "n2.json" || p.Host != "203.0.113.60" || p.Seq != r.Seq || p.By != "test" ||
		!strings.Contains(string(p.Payload), `"address":"203.0.113.60/24"`) {
		t.Fatalf("%+v %v", p, err)
	}
	s, _ := settings.Load(settings.Path(e.dir))
	if !slices.Equal(s.Nodes, []string{"203.0.113.51", "203.0.113.60"}) || s.ZonePrimary().URL != e.turl {
		t.Fatal(s)
	}
	// Its ID pinned where it was adopted, then moved with it; the config's seq recorded.
	l := pins.Open(e.dir)
	if id, err := l.Pinned("203.0.113.60"); err != nil || id != e.node.ID() {
		t.Fatal("pin:", id, err)
	}
	if _, err := l.Pinned("203.0.113.52"); !errors.Is(err, pins.ErrNotPinned) {
		t.Fatal("pin left at the old address:", err)
	}
	if seq, _ := l.Seq(e.node.ID(), "config"); seq != r.Seq {
		t.Fatalf("recorded config seq %d, pushed %d", seq, r.Seq)
	}
	if strings.Contains(e.log(), token) {
		t.Fatal("the token is in the log")
	}
	// Two adopted: the clients' DNS list.
	if !slices.Equal(r.Servers, []string{"203.0.113.60", "203.0.113.51"}) {
		t.Fatal(r.Servers)
	}
}

// A node listed in settings.json by the address it was flashed with: adopted onto another,
// its entry moves with it (in its place), when asked; else the log says to change it.
func TestAdoptListedMoves(t *testing.T) {
	e := newEnv(t)
	settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.52", "203.0.113.51"}, Canary: "203.0.113.52",
		Primary: &primary.Config{Kind: primary.KindTechnitium, URL: e.turl, CertSHA256: e.tpin}})
	r, err := e.adopt(Request{Address: "203.0.113.61/24", AddToSettings: true}, tok(token))
	if err != nil || !r.AddedToSettings {
		t.Fatal(err, r)
	}
	if s, _ := settings.Load(settings.Path(e.dir)); !slices.Equal(s.Nodes, []string{"203.0.113.61", "203.0.113.51"}) || s.Canary != "203.0.113.61" {
		t.Fatal(s)
	}
}

// The address the node runs on, kept (no address given, none in the config): applied live,
// recorded; not added to settings.json unless asked, and the log says so.
func TestAdoptKeepsAddress(t *testing.T) {
	e := newEnv(t)
	r, err := e.adopt(Request{}, tok(token))
	if err != nil {
		t.Fatal(err, e.log())
	}
	if r.Addr != "203.0.113.52" || !r.Recorded || r.AddedToSettings || r.InSettings || slices.Contains(e.node.Events(), "reboot") {
		t.Fatalf("%+v %v", r, e.node.Events())
	}
	if !strings.Contains(e.log(), "static address 203.0.113.52/24, gateway 203.0.113.1 (kept, from its board)") ||
		!strings.Contains(e.log(), "203.0.113.52 is not in settings.json") {
		t.Fatal(e.log())
	}
}

// An address something else answers on, or another node's in settings.json: refused
// before anything changes.
func TestAdoptAddressTaken(t *testing.T) {
	e := newEnv(t)
	_, err := e.adopt(Request{Address: "203.0.113.99/24"}, tok(token))
	if err == nil || !strings.Contains(err.Error(), "3. 203.0.113.99 is in use: something there answers HTTP") {
		t.Fatal(err)
	}
	e.peer.Break(true) // off: still its address
	_, err = e.adopt(Request{Address: "203.0.113.51/24"}, tok(token))
	if err == nil || !strings.Contains(err.Error(), "203.0.113.51 is 203.0.113.51's address") {
		t.Fatal(err)
	}
	if len(e.tech.Sets()) != 0 || len(e.pushes(e.node)) != 0 {
		t.Fatal("changed:", e.tech.Sets(), e.node.Events())
	}
}

// The config's checks for the node (internal/configs), with its network set: a config the
// node's firmware would refuse stops the adoption at step 3.
func TestAdoptConfigCheck(t *testing.T) {
	e := newEnv(t)
	e.config("cpu.json", `{"name": "dns2", "cpu": {"dfs": true}}`)
	_, err := e.adopt(Request{Config: "cpu.json"}, tok(token))
	if err == nil || !strings.HasPrefix(err.Error(), "3. the config") || !strings.Contains(err.Error(), `sets "cpu"`) {
		t.Fatal(err)
	}
	if len(e.pushes(e.node)) != 0 || len(e.tech.Calls()) != 0 {
		t.Fatal("changed:", e.node.Events(), e.tech.Calls())
	}
}

// Without a token: the dry run names the changes to make by hand; the adoption stops
// before anything is pushed until they are confirmed done, then goes on without
// Technitium.
func TestAdoptNoToken(t *testing.T) {
	e := newEnv(t)
	if _, err := e.adopt(Request{DryRun: true}, tok("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log(), "4. by hand: on the zone primary (203.0.113.254), zone home.example, Zone Options: add 203.0.113.52 to Zone Transfer") {
		t.Fatal(e.log())
	}
	_, err := e.adopt(Request{}, tok(""))
	if !errors.Is(err, fleet.ErrManual) || len(e.pushes(e.node)) != 0 {
		t.Fatal(err, e.node.Events())
	}
	if _, err := e.adopt(Request{PrimaryDone: true}, tok("")); err != nil {
		t.Fatal(err)
	}
	if len(e.tech.Calls()) != 0 || len(e.pushes(e.node)) != 1 {
		t.Fatal(e.tech.Calls(), e.node.Events())
	}
	// A token that the API refuses: the dry run fails at step 4, and says why, not the token.
	e2 := newEnv(t)
	_, err = e2.adopt(Request{DryRun: true}, tok("wrong-token-1234"))
	if err == nil || !strings.Contains(err.Error(), "4. home.example: technitium /api/zones/options/get: invalid-token") ||
		strings.Contains(err.Error(), "wrong-token") {
		t.Fatal(err)
	}
}

// No DHCP on a network in settings.json's no_dhcp: a config on DHCP is refused there,
// whatever else. With no no_dhcp (the default) none is assumed: DHCP is offered anywhere.
func TestNoDHCPThere(t *testing.T) {
	e := newEnv(t)
	if _, err := Build(context.Background(), e.client(), e.req(Request{Host: "192.0.2.77", Address: "dhcp", Reserved: true}),
		tok(token), e.logf); err != nil && strings.Contains(err.Error(), "DHCP server") {
		t.Fatal("refused with no no_dhcp:", err)
	}
	s, _ := settings.Load(settings.Path(e.dir))
	s.NoDHCP = []string{"192.0.2.0/23", "192.0.3.128/25"}
	if err := settings.Save(settings.Path(e.dir), s); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), e.client(), e.req(Request{Host: "192.0.2.77", Address: "dhcp", Reserved: true}), tok(token), e.logf)
	if err == nil || !strings.Contains(err.Error(), "192.0.2.0/23, which has no DHCP server (settings.json, no_dhcp)") {
		t.Fatal(err)
	}
	// Elsewhere it is offered, with the reservation.
	b, err := Build(context.Background(), e.client(), e.req(Request{Address: "dhcp"}), tok(token), e.logf)
	if err != nil {
		t.Fatal(err)
	}
	// -host given as a name: the address the node reports is checked at step 3.
	if err := b.Adopt.Check(b.Adopt.Config, release.NodeStatus{IP: "192.0.3.9"}); err == nil ||
		!strings.Contains(err.Error(), "no DHCP server") {
		t.Fatal(err)
	}
}

// A token but no Technitium address (settings.json without "primary", no -primary-url):
// said, not left quietly to changes by hand.
func TestTokenWithoutAddress(t *testing.T) {
	e := newEnv(t)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"}}); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), tok(token), e.logf)
	if err == nil || !strings.Contains(err.Error(), `add "primary"`) {
		t.Fatal(err)
	}
	// Without a token either: the changes by hand, as before.
	if _, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), tok(""), e.logf); err != nil {
		t.Fatal(err)
	}
}

// The manual kind, for any primary: the token is never read (a broken one doesn't matter),
// the dry run names the change per zone in any primary's terms, the adoption stops before
// anything is pushed until it is confirmed made, then goes on with nothing called.
func TestAdoptManualKind(t *testing.T) {
	e := newEnv(t)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"},
		Primary: &primary.Config{Kind: primary.KindManual}}); err != nil {
		t.Fatal(err)
	}
	broken := func() (string, error) { return "", errors.New("read the token") }
	if _, err := e.adopt(Request{DryRun: true}, broken); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.log(), "4. by hand: on the zone primary (203.0.113.254), zone home.example: allow 203.0.113.52 to transfer the zone") ||
		!strings.Contains(e.log(), "zone primary (manual): the zone primary is of kind manual") {
		t.Fatal(e.log())
	}
	b, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), broken, e.logf)
	if err != nil || b.PrimaryKind != primary.KindManual || b.PrimaryAPI != "" || b.PrimaryWhy == "" ||
		!strings.Contains(b.ManualSteps("203.0.113.52")[1], "zone lab.example: allow 203.0.113.52") {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := e.adopt(Request{}, broken); !errors.Is(err, fleet.ErrManual) || len(e.pushes(e.node)) != 0 {
		t.Fatal(err, e.node.Events())
	}
	if _, err := e.adopt(Request{PrimaryDone: true}, broken); err != nil {
		t.Fatal(err)
	}
	if len(e.tech.Calls()) != 0 || len(e.pushes(e.node)) != 1 {
		t.Fatal(e.tech.Calls(), e.node.Events())
	}
	// -primary-kind manual over a technitium primary in settings.json: by hand too.
	e2 := newEnv(t)
	if _, err := e2.adopt(Request{PrimaryKind: primary.KindManual}, tok(token)); !errors.Is(err, fleet.ErrManual) ||
		len(e2.tech.Calls()) != 0 {
		t.Fatal(err, e2.tech.Calls())
	}
	// An address for the manual kind, an unknown kind, an address alone with no API kind
	// to go with it: refused.
	for _, c := range []struct {
		r    Request
		want string
	}{
		{Request{PrimaryKind: "manual", PrimaryURL: "http://203.0.113.254:5380"}, "the manual kind has no API"},
		{Request{PrimaryKind: "bind"}, `-primary-kind: "bind" is not one of manual, technitium`},
		{Request{PrimaryKind: "technitium", PrimaryURL: "http://192.0.2.254:5380"}, "Switch the primary's API to https"},
	} {
		if _, err := Build(context.Background(), e.client(), e.req(c.r), tok(""), e.logf); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.r, err)
		}
	}
	if _, err := Build(context.Background(), e.client(), e.req(Request{PrimaryURL: e2.turl}), tok(token), e.logf); err == nil ||
		!strings.Contains(err.Error(), "give -primary-kind too") {
		t.Fatal(err)
	}
	// -primary-url alone with a technitium primary in settings.json: that kind, this address.
	b, err = Build(context.Background(), e2.client(), e2.req(Request{PrimaryURL: e2.turl, DryRun: true}), tok(token), e2.logf)
	if err != nil || b.PrimaryKind != primary.KindTechnitium || b.PrimaryAPI != e2.turl {
		t.Fatalf("%+v %v", b, err)
	}
}

// No zone primary in settings.json: manual; there is no other default, so a primary is
// never reached unless this deployment names it. A token with nothing to use it on: refused.
func TestAdoptNoPrimaryNoDefault(t *testing.T) {
	e := newEnv(t)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"}}); err != nil {
		t.Fatal(err)
	}
	b, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), tok(""), e.logf)
	if err != nil || b.PrimaryAPI != "" || b.PrimaryKind != primary.KindManual || len(e.tech.Calls()) != 0 {
		t.Fatalf("%+v %v %v", b, err, e.tech.Calls())
	}
	if _, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), tok(token), e.logf); err == nil ||
		!strings.Contains(err.Error(), "a zone primary API token but no zone primary") || len(e.tech.Calls()) != 0 {
		t.Fatal(err)
	}
}

// An address pinned to another node (adopted there before, issue #55) isn't taken over by
// an adoption: whatever answers there now is not signed for until espdns pin says so.
func TestAdoptPinnedToAnother(t *testing.T) {
	e := newEnv(t)
	if _, err := pins.Open(e.dir).Pin("02:00:00:00:00:99", "203.0.113.52"); err != nil {
		t.Fatal(err)
	}
	_, err := e.adopt(Request{Address: "203.0.113.60/24"}, tok(token))
	if err == nil || !strings.Contains(err.Error(), "02:00:00:00:00:99 is pinned there") || len(e.pushes(e.node)) != 0 ||
		len(e.tech.Sets()) != 0 {
		t.Fatal(err, e.node.Events())
	}
	if id, _ := pins.Open(e.dir).Pinned("203.0.113.52"); id != "02:00:00:00:00:99" {
		t.Fatal("pin changed:", id)
	}
}

// The certificate pinned in settings.json goes with its primary only: -primary-url naming
// another address has none pinned (its certificate must be one the system trusts, or be
// pinned in settings.json first).
func TestPinGoesWithItsPrimary(t *testing.T) {
	pin := strings.Repeat("0f", 32)
	s := settings.Settings{Primary: &primary.Config{Kind: primary.KindTechnitium, URL: "https://192.0.2.254:53443", CertSHA256: pin}}
	for url, want := range map[string]string{"": pin, "https://192.0.2.254:53443": pin, "https://192.0.2.253:53443": ""} {
		_, pc, err := Request{PrimaryURL: url}.ZonePrimary(s, tok(token), true, primary.Options{})
		if err != nil || pc.CertSHA256 != want {
			t.Errorf("%q: %+v %v", url, pc, err)
		}
	}
}

// A zone primary in settings.json at a plain http address (saved before https was
// required): adoption goes on, its step 4 paused with the one reason, the changes named to
// make by hand, and the token never sent: the fake primary, over plain http, gets nothing.
func TestAdoptPlainHTTPPrimaryPaused(t *testing.T) {
	e := newEnv(t)
	plain := httptest.NewServer(e.tech)
	t.Cleanup(plain.Close)
	if err := settings.Save(settings.Path(e.dir), settings.Settings{Nodes: []string{"203.0.113.51"},
		Primary: &primary.Config{Kind: primary.KindTechnitium, URL: plain.URL}}); err != nil {
		t.Fatal(err)
	}
	b, err := Build(context.Background(), e.client(), e.req(Request{DryRun: true}), tok(token), e.logf)
	if err != nil || b.PrimaryAPI != "" || b.PrimaryWhy != primary.ErrPlainHTTP.Error() {
		t.Fatalf("%+v %v", b, err)
	}
	if _, err := e.adopt(Request{}, tok(token)); !errors.Is(err, fleet.ErrManual) {
		t.Fatal(err)
	}
	if !strings.Contains(e.log(), "4. by hand:") {
		t.Fatal(e.log())
	}
	if _, err := e.adopt(Request{PrimaryDone: true}, tok(token)); err != nil {
		t.Fatal(err)
	}
	if len(e.tech.Calls()) != 0 {
		t.Fatal("sent to a plain http primary:", e.tech.Calls())
	}
	// -primary-url plain http, given now: refused
	if _, err := Build(context.Background(), e.client(), e.req(Request{PrimaryURL: plain.URL}), tok(token), e.logf); err == nil ||
		!strings.Contains(err.Error(), "-primary-url") || !errors.Is(err, primary.ErrPlainHTTP) {
		t.Fatal(err)
	}
}
