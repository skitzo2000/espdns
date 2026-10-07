package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/inventory"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zonefiles"
)

// fakeZonePrimary is a zone primary over DNS, whatever its software: it answers an SOA
// query for a zone it holds authoritatively, refuses everything else, and records who was
// asked. No query leaves the test.
type fakeZonePrimary struct {
	mu    sync.Mutex
	at    string
	zones map[string]uint32
	asked []string
}

func (f *fakeZonePrimary) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, host)
	r := new(dns.Msg)
	r.SetReply(m)
	q := strings.TrimSuffix(m.Question[0].Name, ".")
	serial, ok := f.zones[q]
	if host != f.at || !ok || m.RecursionDesired || m.Question[0].Qtype != dns.TypeSOA {
		r.Rcode = dns.RcodeRefused
		return r, nil
	}
	r.Authoritative = true
	r.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(q), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns: "ns1." + dns.Fqdn(q), Mbox: "hostmaster." + dns.Fqdn(q), Serial: serial}}
	return r, nil
}

func (f *fakeZonePrimary) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.asked...)
}

// The zone inventory and the lookup over HTTP: a login (its session token) needed; every
// zone with its source and the fleet's state, never a node's; the zone primary without its
// token; a lookup that finds the fleet's zone, a zone on the primary (over DNS, from the
// fake), and none; a name that isn't one refused before any query.
func TestZoneInventoryAPI(t *testing.T) {
	dir := t.TempDir()
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{"192.0.2.11", "192.0.2.12"},
		Primary: &primary.Config{Kind: primary.KindTechnitium, URL: "https://192.0.2.254:53443"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.ImportDataToken(dir, "a-secret-token", false); err != nil {
		t.Fatal(err)
	}
	if _, err := zonefiles.Save(dir, "home.example.zone", []byte("$TTL 3600\n@ IN SOA ns1.home.example. hostmaster.home.example. "+
		"( 5 3600 600 604800 300 )\n  IN NS ns1\nns1 IN A 192.0.2.53\n"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := configs.Save(dir, "a.json", []byte(`{"name": "a", "secondary": {"primary": "192.0.2.254", "zones": ["lab.example"]},
		"forward_zones": [{"zone": "corp.example", "forwarder": "198.51.100.53"}]}`), ""); err != nil {
		t.Fatal(err)
	}
	st := map[string]any{"zones": []any{map[string]any{"name": "lab.example", "expired": false}},
		"forward_zones": []any{map[string]any{"name": "corp.example", "forwarder": "198.51.100.53"}},
		"hosted":        map[string]any{"state": "on", "zones": []any{map[string]any{"name": "home.example", "serial": 5, "records": 3}}}}
	ns := []nodes.Node{{Addr: "192.0.2.11", Online: true, Status: st}, {Addr: "192.0.2.12", Online: true, Status: st},
		{Addr: "192.0.2.99", Online: true, Status: map[string]any{"zones": []any{map[string]any{"name": "stray.example"}}}}}
	fp := &fakeZonePrimary{at: "192.0.2.254", zones: map[string]uint32{"new.example": 42, "lab.example": 7}}
	s := &server{dataDir: dir, auth: auth.New(auth.Path(dir)), runner: jobs.New(dir, map[string]jobs.Kind{}),
		key: keys.FileSource{Path: keys.Path(dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()),
		nodes: func() []nodes.Node { return ns }, zoneDNS: fp}
	h, _ := s.handler()
	cookie, tok := login(t, h)
	get := func(path string, session bool) (int, string) {
		r := httptest.NewRequest("GET", "http://127.0.0.1:8480"+path, nil)
		if session {
			r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
			r.Header.Set(auth.TokenHeader, tok)
		}
		w := serve(h, r)
		return w.Code, w.Body.String()
	}

	// The session model: no cookie, or the cookie without its token, is refused.
	for _, p := range []string{"/api/zone-inventory", "/api/zone-lookup?name=new.example"} {
		if code, _ := get(p, false); code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d", p, code)
		}
		r := httptest.NewRequest("GET", "http://127.0.0.1:8480"+p, nil)
		r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
		if w := serve(h, r); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the token: %d", p, w.Code)
		}
	}
	if len(fp.calls()) != 0 {
		t.Fatalf("a refused lookup asked the primary: %v", fp.calls())
	}

	code, body := get("/api/zone-inventory", true)
	if code != 200 {
		t.Fatalf("inventory: %d %s", code, body)
	}
	var inv struct {
		inventory.Inventory
		Primary map[string]any `json:"primary"`
	}
	if err := json.Unmarshal([]byte(body), &inv); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, z := range inv.Zones {
		got = append(got, z.Name+" "+z.Kind+" "+z.State)
	}
	// The node not in settings.json (192.0.2.99) isn't the fleet: its stray zone isn't listed.
	if strings.Join(got, ", ") != "corp.example forward ok, home.example hosted ok, lab.example secondary ok" {
		t.Errorf("zones: %v", got)
	}
	if inv.Fleet != 2 || inv.Nodes != 2 || strings.Join(inv.Primaries, ",") != "192.0.2.254" {
		t.Errorf("inventory: %+v", inv.Inventory)
	}
	if inv.Primary["kind"] != "technitium" || inv.Primary["url"] != "https://192.0.2.254:53443" || inv.Primary["api"] != true ||
		inv.Primary["set"] != true {
		t.Errorf("primary: %v", inv.Primary)
	}
	for _, leak := range []string{"a-secret-token", "192.0.2.11", "192.0.2.12"} {
		if strings.Contains(body, leak) {
			t.Errorf("the inventory holds %q: %s", leak, body)
		}
	}

	lookup := func(name string) inventory.Lookup {
		t.Helper()
		code, body := get("/api/zone-lookup?name="+name, true)
		var l inventory.Lookup
		if code != 200 || json.Unmarshal([]byte(body), &l) != nil {
			t.Fatalf("lookup %s: %d %s", name, code, body)
		}
		return l
	}
	if l := lookup("Lab.Example."); l.Found != inventory.FoundZone || l.Name != "lab.example" || l.Zone == nil ||
		l.Zone.Primary != "192.0.2.254" || len(l.Tried) != 0 {
		t.Errorf("lab: %+v", l)
	}
	if len(fp.calls()) != 0 {
		t.Errorf("a zone of the fleet's asked the primary: %v", fp.calls())
	}
	if l := lookup("new.example"); l.Found != inventory.FoundPrimary || l.Primary != "192.0.2.254" || l.Serial != 42 {
		t.Errorf("new: %+v", l)
	}
	// settings.json's primary and the configs' are the same server: asked once.
	if c := fp.calls(); len(c) != 1 || c[0] != "192.0.2.254" {
		t.Errorf("asked: %v", c)
	}
	if l := lookup("nowhere.example"); l.Found != inventory.FoundNone || len(l.Tried) != 1 || !strings.HasPrefix(l.Tried[0].Answer, "refused") {
		t.Errorf("nowhere: %+v", l)
	}
	before := len(fp.calls())
	for _, bad := range []string{"", "a..b", "-x.example", "a%20b", "x/y"} {
		if code, _ := get("/api/zone-lookup?name="+bad, true); code != http.StatusBadRequest {
			t.Errorf("lookup %q: %d", bad, code)
		}
	}
	if len(fp.calls()) != before {
		t.Errorf("a refused name asked the primary: %v", fp.calls())
	}
}

// The primaries a lookup asks: settings.json's first (its API's host), then the configs',
// each once; none set up, only the configs'.
func TestLookupPrimaries(t *testing.T) {
	inv := inventory.Inventory{Primaries: []string{"192.0.2.253", "192.0.2.254"}}
	s := settings.Settings{Primary: &primary.Config{Kind: primary.KindTechnitium, URL: "https://192.0.2.254:53443"}}
	if got := strings.Join(primaries(s, inv), ","); got != "192.0.2.254,192.0.2.253" {
		t.Errorf("got %s", got)
	}
	if got := strings.Join(primaries(settings.Settings{Primary: &primary.Config{Kind: primary.KindManual}}, inv), ","); got != "192.0.2.253,192.0.2.254" {
		t.Errorf("manual: %s", got)
	}
	if got := primaries(settings.Settings{}, inventory.Inventory{}); len(got) != 0 {
		t.Errorf("none: %v", got)
	}
}
