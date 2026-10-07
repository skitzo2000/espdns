package primary

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/faketech"
)

// The technitium driver against the fake Technitium (internal/faketech), as Open makes it:
// on a name-server server and on an ACL server, a node allowed in and taken off again,
// the dry run reading only, each change reported; the manual text its own.
func TestTechnitiumDriverFake(t *testing.T) {
	const tok = "0123456789abcdef-test-token"
	for _, acl := range []bool{false, true} {
		fake := faketech.New(tok, "home.example")
		fake.ACL = acl
		srv := httptest.NewTLSServer(fake)
		t.Cleanup(srv.Close)
		// Its own certificate (self-signed), pinned
		c := Config{Kind: KindTechnitium, URL: srv.URL, CertSHA256: Fingerprint(srv.Certificate())}
		var edits []Edit
		dry, err := Open(c, tok, Options{DryRun: true, Report: func(e Edit) { edits = append(edits, e) }})
		if err != nil || dry.Ready() != nil || dry.Kind() != KindTechnitium || dry.API() != srv.URL {
			t.Fatal(err, dry)
		}
		if err := dry.Allow(context.Background(), "home.example", "203.0.113.60"); err != nil {
			t.Fatal(err)
		}
		if len(fake.Sets()) != 0 || len(edits) != 1 || edits[0].Applied || len(edits[0].Changes) == 0 {
			t.Fatal(acl, fake.Sets(), edits)
		}
		p, _ := Open(c, tok, Options{})
		if err := p.Allow(context.Background(), "home.example", "203.0.113.60"); err != nil {
			t.Fatal(err)
		}
		l, err := p.Lists(context.Background(), "home.example")
		if tr, no := l.Has("203.0.113.60"); err != nil || !tr || !no || l.TransferACL != acl {
			t.Fatalf("acl %v: %+v %v", acl, l, err)
		}
		if err := p.Remove(context.Background(), "home.example", "203.0.113.60"); err != nil {
			t.Fatal(err)
		}
		if z, _ := fake.Zone("home.example"); len(z.TransferList) != 0 || len(z.NotifyList) != 0 {
			t.Fatal(z)
		}
		if m := p.Manual("203.0.113.254", "home.example", "203.0.113.60"); !strings.Contains(m, "zone home.example, Zone Options: add 203.0.113.60") {
			t.Fatal(m)
		}
		// A wrong token: the API's refusal, never the token.
		bad, _ := Open(c, "wrong-token-1234", Options{})
		if _, err := bad.Lists(context.Background(), "home.example"); err == nil || strings.Contains(err.Error(), "wrong-token") ||
			!strings.Contains(err.Error(), "invalid-token") {
			t.Fatal(err)
		}
	}
}

// Open: the manual kind (any primary) and an API kind without its address or token are
// changed by hand, saying why, and never reach anything; an unknown kind is an error.
func TestOpenByHand(t *testing.T) {
	for _, c := range []struct{ kind, url, tok, why string }{
		{KindManual, "", "", "kind manual"},
		{KindManual, "", "a-token-123", "kind manual"},
		{KindTechnitium, "", "a-token-123", "no Technitium API address"},
		{KindTechnitium, "https://192.0.2.254:53443", "", "no zone primary API token"},
	} {
		p, err := Open(Config{Kind: c.kind, URL: c.url}, c.tok, Options{})
		if err != nil || !errors.Is(p.Ready(), ErrByHand) || !strings.Contains(Why(p), c.why) || p.API() != "" || p.Kind() != c.kind {
			t.Fatalf("%+v: %v %v", c, p, err)
		}
		if _, err := p.Lists(context.Background(), "home.example"); !errors.Is(err, ErrByHand) {
			t.Fatal(err)
		}
		if err := p.Allow(context.Background(), "home.example", "203.0.113.60"); !errors.Is(err, ErrByHand) {
			t.Fatal(err)
		}
		if err := p.Remove(context.Background(), "home.example", "203.0.113.60"); !errors.Is(err, ErrByHand) {
			t.Fatal(err)
		}
	}
	m, _ := Open(Config{Kind: KindManual}, "", Options{})
	if s := m.Manual("203.0.113.254", "home.example", "203.0.113.60"); !strings.Contains(s, "on the zone primary (203.0.113.254), zone home.example: allow 203.0.113.60 to transfer") ||
		!strings.Contains(s, "also-notify") {
		t.Fatal(s)
	}
	t1, _ := Open(Config{Kind: KindTechnitium}, "", Options{})
	if s := t1.Manual("", "home.example", "203.0.113.60"); !strings.Contains(s, "Zone Options") {
		t.Fatal(s)
	}
	if _, err := Open(Config{Kind: "bind"}, "", Options{}); err == nil || !strings.Contains(err.Error(), "manual, technitium") {
		t.Fatal(err)
	}
	if _, err := Open(Config{Kind: KindTechnitium, URL: "https://x/api"}, "a-token-123", Options{}); err == nil {
		t.Fatal("a bad address opened")
	}
	if !slices.Equal(Kinds(), []string{KindManual, KindTechnitium}) {
		t.Fatal(Kinds())
	}
}

// A plain http API address is refused wherever it is given, loopback too, saying to switch
// the primary's API to https (in the driver's words) and pin its certificate. One already
// saved (CheckSaved) is let through, and Open makes it a paused primary: never reached,
// the token never sent, its one reason ErrPlainHTTP.
func TestPlainHTTPRefused(t *testing.T) {
	var sent int
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent++ }))
	defer plain.Close()
	for _, u := range []string{"http://192.0.2.254:5380", "http://127.0.0.1:5380", "http://localhost:5380", "HTTP://primary.example", plain.URL} {
		c := Config{Kind: KindTechnitium, URL: u}
		err := c.Check()
		if err == nil || !errors.Is(err, ErrPlainHTTP) || !strings.Contains(err.Error(), "plain http") || !strings.Contains(err.Error(), "Switch the primary's API to https") ||
			!strings.Contains(err.Error(), "Technitium: Settings, Web Service, enable HTTPS") || !strings.Contains(err.Error(), "pinned") {
			t.Errorf("%s: %v", u, err)
		}
		if err := c.CheckSaved(); err != nil || !c.PlainHTTP() {
			t.Errorf("%s saved: %v %v", u, err, c.PlainHTTP())
		}
		for _, tok := range []string{"a-token-123", ""} {
			p, err := Open(c, tok, Options{})
			if err != nil || p.API() != "" || !errors.Is(p.Ready(), ErrPlainHTTP) || !errors.Is(p.Ready(), ErrByHand) || Why(p) != ErrPlainHTTP.Error() {
				t.Fatalf("%s: %v %v", u, p, err)
			}
			if _, err := p.Lists(context.Background(), "home.example"); !errors.Is(err, ErrPlainHTTP) {
				t.Fatal(err)
			}
			if err := p.Allow(context.Background(), "home.example", "203.0.113.60"); !errors.Is(err, ErrPlainHTTP) {
				t.Fatal(err)
			}
			if err := p.Remove(context.Background(), "home.example", "203.0.113.60"); !errors.Is(err, ErrPlainHTTP) {
				t.Fatal(err)
			}
		}
	}
	if sent != 0 {
		t.Fatalf("%d requests to a plain http primary", sent)
	}
	if (Config{Kind: KindTechnitium, URL: "https://x"}).PlainHTTP() || (Config{Kind: KindManual}).PlainHTTP() {
		t.Fatal("PlainHTTP")
	}
	if err := (Config{Kind: KindManual, URL: "http://x:1"}).CheckSaved(); err == nil {
		t.Fatal("an address for the manual kind let through")
	}
}

// A Technitium made by hand over plain http (Open never makes one) still never sends the
// token: refused before anything is sent. So is a request over plain http through Client.
func TestTechnitiumNeverInClear(t *testing.T) {
	sent := false
	hc := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		sent = true
		return nil, errors.New("sent")
	})}
	tc := &Technitium{URL: "http://192.0.2.254:5380", Token: "a-token-123", HTTP: hc}
	if _, err := tc.Lists(context.Background(), "home.example"); err == nil || !strings.Contains(err.Error(), "isn't https") || sent {
		t.Fatalf("%v (sent %v)", err, sent)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sent = true }))
	t.Cleanup(plain.Close)
	if _, err := Client(Config{}).Get(plain.URL); !errors.Is(err, errPlainAPI) || sent {
		t.Fatalf("%v (sent %v)", err, sent)
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Config: the kinds and their addresses, as settings.json's "primary" is checked.
func TestConfigCheck(t *testing.T) {
	for _, c := range []struct {
		c  Config
		ok bool
	}{
		{Config{Kind: "manual"}, true},
		{Config{Kind: "technitium", URL: "https://192.0.2.254:53443"}, true},
		{Config{Kind: "technitium", URL: "https://dns.example"}, true},
		{Config{Kind: "technitium", URL: "https://dns.example", CertSHA256: strings.Repeat("ab", 32)}, true},
		{Config{Kind: "technitium", URL: "http://192.0.2.254:5380"}, false},
		{Config{Kind: "technitium", URL: "https://dns.example", CertSHA256: strings.Repeat("AB", 32)}, false},
		{Config{Kind: "technitium", URL: "https://dns.example", CertSHA256: "ab:cd"}, false},
		{Config{Kind: "manual", CertSHA256: strings.Repeat("ab", 32)}, false},
		{Config{}, false},
		{Config{Kind: "bind"}, false},
		{Config{Kind: "manual", URL: "http://x:1"}, false},
		{Config{Kind: "technitium"}, false},
		{Config{Kind: "technitium", URL: "192.0.2.254:5380"}, false},
		{Config{Kind: "technitium", URL: "https://u:p@x"}, false},
		{Config{Kind: "technitium", URL: "https://x?token=1"}, false},
	} {
		if err := c.c.Check(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.c, err)
		}
	}
}

// Technitium: the node's address is added to both lists, and a zone that allowed only
// its own name servers now allows the listed ones too; an address already there changes
// nothing.
func TestTechnitiumAllow(t *testing.T) {
	var set url.Values
	opts := `{"zoneTransfer":"AllowOnlyZoneNameServers","zoneTransferNameServers":[],"notify":"ZoneNameServers","notifyNameServers":[]}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.URL.Path == "/api/zones/options/set" {
			set = r.Form
		}
		rw.Write([]byte(`{"status":"ok","response":` + opts + `}`))
	}))
	defer srv.Close()
	tc := &Technitium{URL: srv.URL, Token: "tok", HTTP: srv.Client()}
	if err := tc.Allow(context.Background(), "home.example", "192.0.2.252"); err != nil {
		t.Fatal(err)
	}
	if set.Get("zoneTransferNameServers") != "192.0.2.252" || set.Get("notifyNameServers") != "192.0.2.252" ||
		set.Get("zoneTransfer") != "AllowBothZoneAndSpecifiedNameServers" || set.Get("notify") != "BothZoneAndSpecifiedNameServers" ||
		set.Get("zone") != "home.example" {
		t.Fatal(set)
	}
	set = nil
	opts = `{"zoneTransfer":"UseSpecifiedNetworkACL","zoneTransferNetworkACL":["192.0.2.252"],"notify":"SpecifiedNameServers","notifyNameServers":["192.0.2.252"]}`
	if err := tc.Allow(context.Background(), "home.example", "192.0.2.252"); err != nil || set != nil {
		t.Fatal(err, set)
	}
	if err := tc.Remove(context.Background(), "home.example", "192.0.2.252"); err != nil ||
		set.Get("zoneTransferNetworkACL") != "false" || set.Get("notifyNameServers") != "false" || set.Get("zoneTransfer") != "" {
		t.Fatal(err, set)
	}
}

// The token never comes back in an error, as sent or form-encoded, and a redirect is never
// followed (a 307 would send the form, token and all, wherever it points).
func TestTechnitiumTokenKept(t *testing.T) {
	tok := "a+b/c&d=e%f-0123"
	var elsewhere bool
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere = true }))
	t.Cleanup(other.Close)
	echo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/api/zones/options/set" {
			http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
			return
		}
		fmt.Fprintf(w, `{"status":"error","errorMessage":"bad request: %s / %s"}`, b, url.QueryEscape(tok))
	}))
	t.Cleanup(echo.Close)
	tc := &Technitium{URL: echo.URL, Token: tok, HTTP: echo.Client()}
	_, err := tc.Lists(context.Background(), "home.example")
	if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), url.QueryEscape(tok)) ||
		!strings.Contains(err.Error(), "[token]") {
		t.Fatal(err)
	}
	if err := tc.call(context.Background(), "/api/zones/options/set", url.Values{}, nil); err == nil || elsewhere {
		t.Fatal("redirect followed:", err, elsewhere)
	}
}

// Has reads only what the driver says the modes mean, never a server's mode names: a
// driver for another primary fills TransferAll, TransferUses and NotifyUses from its own.
func TestListsHasDriverNeutral(t *testing.T) {
	l := Lists{Zone: "z", Transfer: "Allow", TransferList: []string{"198.51.100.5"}, Notify: "SpecifiedNameServers",
		NotifyList: []string{"198.51.100.5"}}
	if tr, no := l.Has("198.51.100.5"); tr || no {
		t.Fatal("modes alone counted")
	}
	l.TransferUses, l.NotifyUses = true, true
	if tr, no := l.Has("198.51.100.5"); !tr || !no {
		t.Fatal(tr, no)
	}
	if tr, _ := l.Has("198.51.100.6"); tr {
		t.Fatal("not listed")
	}
	l = Lists{TransferAll: true, TransferACL: true, TransferUses: true, TransferList: []string{"203.0.113.0/24"}}
	if tr, no := l.Has("198.51.100.6"); !tr || no {
		t.Fatal(tr, no)
	}
	l.TransferAll = false
	if tr, _ := l.Has("203.0.113.3"); !tr {
		t.Fatal("in the ACL's network")
	}
	if got := APIKinds(); len(got) != 1 || got[0] != KindTechnitium {
		t.Fatal(got)
	}
}
