package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/adoption"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/faketech"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

const techToken = "0123456789abcdef-test-token"

// adoptWorld is a data directory (settings.json with a node in service and the Technitium
// API, a config, the Technitium token imported), a fake network with that node and one to
// adopt, and a fake Technitium.
type adoptWorld struct {
	data, catalog string
	lan           *fakenode.Lan
	node, peer    *fakenode.Node
	tech          *faketech.Server
	turl          string
	key           *ecdsa.PrivateKey
}

func newAdoptWorld(t *testing.T) *adoptWorld {
	t.Setenv(envPrimaryToken, "")
	w := &adoptWorld{data: t.TempDir(), catalog: t.TempDir(), lan: fakenode.NewLan()}
	t.Cleanup(w.lan.Close)
	w.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	put(t, filepath.Join(w.catalog, "p4-ip101.json"), []byte(`{"name": "p4-ip101", "image": "esp32p4-rev1"}`))
	for i, name := range []string{"dns1", "new"} {
		n := fakenode.New(name, [6]byte{2, 0, 0, 0, 0, byte(0x51 + i)}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(w.key))
		n.Addr, n.Gateway, n.Unadopted, n.DownFor = []string{"203.0.113.51", "203.0.113.52"}[i], "203.0.113.1", i == 1, 20*time.Millisecond
		w.lan.Add(n)
		if i == 0 {
			w.peer = n
		} else {
			w.node = n
		}
	}
	w.tech = faketech.New(techToken, "home.example", "lab.example")
	ts := httptest.NewTLSServer(w.tech) // its own certificate, pinned below
	t.Cleanup(ts.Close)
	w.turl = ts.URL
	if err := settings.Save(settings.Path(w.data), settings.Settings{Nodes: []string{"203.0.113.51"}, DNSPeers: []string{"203.0.113.254"},
		DNSPeerZones: []string{"home.example"}, Primary: &primary.Config{Kind: primary.KindTechnitium, URL: w.turl,
			CertSHA256: primary.Fingerprint(ts.Certificate())}}); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(configs.Path(w.data), "n2.json"), []byte(`{"name": "dns2", "forwarders": ["9.9.9.9"], `+
		`"secondary": {"primary": "203.0.113.254", "zones": ["home.example", "lab.example"]}}`))
	if _, err := keys.ImportToken(keys.TokenPath(w.data), techToken, false); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *adoptWorld) client() *fleet.Client {
	hc := w.lan.HTTP()
	return &fleet.Client{HTTP: hc, DNS: w.lan, PeerDNS: w.lan, Poll: 10 * time.Millisecond, Logf: func(string, ...any) {},
		Pusher: &release.Pusher{Key: w.key, KeyID: release.KeyRelease, Pins: pins.Open(w.data), Client: hc}}
}

// adoptView is what an adoption does, without its hooks: what two builds are compared on.
type adoptView struct {
	Host, ID, Address, Gateway string
	DHCP, Reserved, ManualDone bool
	Payload                    string
	Identify, Wait             time.Duration
	Peers                      []string
	DNSPeers                   []fleet.DNSPeer
	AllowSingle, Force, DryRun bool
	Checks                     fleet.Checks
	Kind, TURL, TToken         string
	TDry, CheckSet             bool
	ConfigName, Primary        string
	Zones                      []string
	Why                        string
}

func viewOf(t *testing.T, b adoption.Built) adoptView {
	a := b.Adopt
	p, err := a.Config.Payload()
	if err != nil {
		t.Fatal(err)
	}
	v := adoptView{Host: a.Host, ID: a.ID, Address: a.Address.String(), Gateway: a.Gateway.String(), DHCP: a.DHCP,
		Reserved: a.Reserved, ManualDone: a.ManualDone, Payload: string(p), Identify: a.Identify, Wait: a.ConfirmWait,
		Peers: a.Peers, DNSPeers: a.DNSPeers, AllowSingle: a.AllowSingle, Force: a.Force, DryRun: a.DryRun, Checks: a.Checks,
		CheckSet: a.Check != nil, ConfigName: b.ConfigName, Primary: b.Primary, Zones: b.Zones, Kind: b.PrimaryKind,
		Why: b.PrimaryWhy}
	if tc, ok := a.Primary.(*primary.Technitium); ok {
		v.TURL, v.TToken, v.TDry = tc.URL, tc.Token, tc.DryRun
	}
	return v
}

// The CLI's flags, as make fleet-adopt[-dry] passes them, and the Adopt page's request for
// the same adoption make the same request, and it builds into the same adoption: the same
// node and ID, the same address and gateway (or DHCP with its reservation), the same
// config payload and checks, the same peers and DNS peers for the rule, the same zone
// primary (Technitium's API with the same token: the environment's in the CLI, the controller's
// copy on the page, here one token; or the manual kind), the same manual confirmation. So
// the page adopts as the Makefile does, not with a copy of it.
func TestCLIAndAdoptPageBuildTheSameAdoption(t *testing.T) {
	w := newAdoptWorld(t)
	id := w.node.ID()
	cfg := filepath.Join(configs.Path(w.data), "n2.json")
	base := []string{"-key", "-", "-data", w.data, "-mdns", "0", "-host", "203.0.113.52", "-node", id, "-config", cfg,
		"-catalog", w.catalog}
	tech := primary.Config{Kind: primary.KindTechnitium, URL: w.turl}
	manual := primary.Config{Kind: primary.KindManual}
	newFlags := []string{"-primary-kind", "technitium", "-primary-url", w.turl}
	for _, tc := range []struct {
		name string
		set  primary.Config
		cli  []string
		web  string
	}{
		{"the address it runs on, dry run", tech, append(slices.Clone(newFlags), "-dry-run"),
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","dry_run":true}`},
		{"a new address and gateway", tech, append(slices.Clone(newFlags), "-address", "203.0.113.60/24", "-gateway", "203.0.113.1"),
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","address":"203.0.113.60/24","gateway":"203.0.113.1"}`},
		{"added to settings, done by hand", tech, append(slices.Clone(newFlags), "-add-to-settings", "-primary-done"),
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","add_to_settings":true,"primary_done":true}`},
		{"DHCP, reserved (on no network in no_dhcp)", tech, append(slices.Clone(newFlags), "-address", "dhcp", "-reserved", "-dry-run"),
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","address":"dhcp","reserved":true,"dry_run":true}`},
		{"the manual kind, dry run", manual, []string{"-primary-kind", "manual", "-dry-run"},
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","dry_run":true}`},
		{"the manual kind, done by hand", manual, []string{"-primary-kind", "manual", "-primary-done", "-add-to-settings"},
			`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","add_to_settings":true,"primary_done":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := settings.Load(settings.Path(w.data))
			s.Primary = &tc.set
			if err := settings.Save(settings.Path(w.data), s); err != nil {
				t.Fatal(err)
			}
			cliReq, _, tf, err := adoptRequest(append(slices.Clone(base), tc.cli...))
			if err != nil || tf != (tokenFrom{}) {
				t.Fatal(err, tf)
			}
			web, err := adoption.ParseWeb([]byte(tc.web))
			if err != nil {
				t.Fatal(err)
			}
			webReq, err := web.Request(w.data, w.catalog)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cliReq, webReq) {
				t.Fatalf("requests differ:\nCLI %+v\npage %+v", cliReq, webReq)
			}
			ctx := context.Background()
			cliB, err := adoption.Build(ctx, w.client(), cliReq, cliToken(tokenFrom{}, w.data), func(string, ...any) {})
			if err != nil {
				t.Fatal(err)
			}
			webB, err := adoption.Build(ctx, w.client(), webReq, func() (string, error) {
				t, err := keys.DataTokenSource{DataDir: w.data}.Token()
				if errors.Is(err, keys.ErrNoToken) {
					return "", nil
				}
				return t, err
			}, func(string, ...any) {})
			if err != nil {
				t.Fatal(err)
			}
			cv, wv := viewOf(t, cliB), viewOf(t, webB)
			if !reflect.DeepEqual(cv, wv) {
				t.Fatalf("adoptions differ:\nCLI %+v\npage %+v", cv, wv)
			}
			want := adoptView{Kind: "technitium", TToken: techToken, TURL: w.turl}
			if tc.set.Kind == primary.KindManual {
				want = adoptView{Kind: "manual", Why: "the zone primary is of kind manual: any primary, its lists changed by hand"}
			}
			if cv.Kind != want.Kind || cv.TToken != want.TToken || cv.TURL != want.TURL || cv.Why != want.Why ||
				!slices.Equal(cv.Peers, []string{"203.0.113.51"}) || len(cv.DNSPeers) != 1 || !cv.CheckSet ||
				cv.Wait != adoption.DefaultWait || !slices.Equal(cv.Checks.Forwarded, []string{"example.com"}) {
				t.Fatalf("%+v", cv)
			}
		})
	}
}

// settings.json's no_dhcp: the CLI's flags and the Adopt page's request for DHCP on a
// network named there are refused the same way, from the same setting.
func TestCLIAndAdoptPageNoDHCP(t *testing.T) {
	w := newAdoptWorld(t)
	s, _ := settings.Load(settings.Path(w.data))
	s.NoDHCP = []string{"203.0.113.0/24"}
	if err := settings.Save(settings.Path(w.data), s); err != nil {
		t.Fatal(err)
	}
	id := w.node.ID()
	cliReq, _, _, err := adoptRequest([]string{"-key", "-", "-data", w.data, "-mdns", "0", "-host", "203.0.113.52", "-node", id,
		"-config", filepath.Join(configs.Path(w.data), "n2.json"), "-catalog", w.catalog, "-primary-kind", "manual",
		"-address", "dhcp", "-reserved", "-dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	web, err := adoption.ParseWeb([]byte(`{"node":"203.0.113.52","node_id":"` + id + `","config":"n2.json","address":"dhcp","reserved":true,"dry_run":true}`))
	if err != nil {
		t.Fatal(err)
	}
	webReq, err := web.Request(w.data, w.catalog)
	if err != nil {
		t.Fatal(err)
	}
	none := func() (string, error) { return "", nil }
	_, cerr := adoption.Build(context.Background(), w.client(), cliReq, none, func(string, ...any) {})
	_, werr := adoption.Build(context.Background(), w.client(), webReq, none, func(string, ...any) {})
	if cerr == nil || werr == nil || cerr.Error() != werr.Error() || !strings.Contains(cerr.Error(), "203.0.113.0/24, which has no DHCP server") {
		t.Fatal(cerr, werr)
	}
}

// The token's flags; the old names (-technitium, its $TECHNITIUM_URL default,
// -technitium-token-file, -technitium-done, the page's "technitium_done") are gone.
func TestAdoptPrimaryFlags(t *testing.T) {
	w := newAdoptWorld(t)
	base := []string{"-data", w.data, "-host", "203.0.113.52"}
	r, _, tf, err := adoptRequest(append(slices.Clone(base), "-primary-token-file", "/t", "-primary-token-env", "TOKEN_NAME"))
	if err != nil || tf != (tokenFrom{file: "/t", env: "TOKEN_NAME"}) || r.PrimaryKind != "" {
		t.Fatal(err, tf, r.PrimaryKind)
	}
	t.Setenv("TECHNITIUM_URL", w.turl)
	if r, _, _, err := adoptRequest(base); err != nil || r.PrimaryKind != "" || r.PrimaryURL != "" {
		t.Fatal(err, r.PrimaryKind, r.PrimaryURL)
	}
	if _, err := adoption.ParseWeb([]byte(`{"node":"203.0.113.52","technitium_done":true}`)); err == nil {
		t.Fatal(`the page's old "technitium_done" taken`)
	}
}

func rmToken(t *testing.T, data string) {
	if err := os.Remove(keys.TokenPath(data)); err != nil {
		t.Fatal(err)
	}
}

// espdns adopt as make fleet-adopt runs it: the node adopted, the zone primary's lists
// changed with the token from the data directory (none in the environment here), the config it runs
// recorded by the CLI, and with -add-to-settings its address in settings.json.
func TestCLIAdoptRecords(t *testing.T) {
	w := newAdoptWorld(t)
	keyFile := filepath.Join(t.TempDir(), "release.pem")
	pem, _ := keys.Encode(w.key)
	put(t, keyFile, pem)
	old := adoptClient
	t.Cleanup(func() { adoptClient = old })
	adoptClient = func(o *fleetOpts) (*fleet.Client, error) {
		c, err := o.client()
		if err != nil {
			return nil, err
		}
		hc := w.lan.HTTP()
		c.HTTP, c.DNS, c.PeerDNS, c.Poll, c.Pusher.Client = hc, w.lan, w.lan, 10*time.Millisecond, hc
		return c, nil
	}
	args := []string{"-key", keyFile, "-data", w.data, "-mdns", "0", "-host", "203.0.113.52", "-node", w.node.ID(),
		"-config", "n2.json", "-address", "203.0.113.60/24", "-catalog", w.catalog, "-add-to-settings", "-wait", "5s"}
	if err := cmdAdopt(args); err != nil {
		t.Fatal(err)
	}
	p, err := configs.LoadPushed(w.data, w.node.ID())
	if err != nil || p == nil || p.By != "cli" || p.File != "n2.json" || p.Host != "203.0.113.60" {
		t.Fatalf("%+v %v", p, err)
	}
	s, _ := settings.Load(settings.Path(w.data))
	if !slices.Equal(s.Nodes, []string{"203.0.113.51", "203.0.113.60"}) {
		t.Fatal(s.Nodes)
	}
	if z, _ := w.tech.Zone("lab.example"); !slices.Equal(z.TransferList, []string{"203.0.113.60"}) {
		t.Fatal(z)
	}
	// No token anywhere and no -technitium-done: refused before anything is pushed, saying
	// how to go on.
	w2 := newAdoptWorld(t)
	adoptClient = func(o *fleetOpts) (*fleet.Client, error) {
		c, err := o.client()
		if err != nil {
			return nil, err
		}
		hc := w2.lan.HTTP()
		c.HTTP, c.DNS, c.PeerDNS, c.Poll, c.Pusher.Client = hc, w2.lan, w2.lan, 10*time.Millisecond, hc
		return c, nil
	}
	put(t, keys.TokenPath(w2.data), nil)
	err = cmdAdopt([]string{"-key", keyFile, "-data", w2.data, "-mdns", "0", "-host", "203.0.113.52", "-config", "n2.json",
		"-catalog", w2.catalog})
	if err == nil || !strings.Contains(err.Error(), "the zone primary API token") {
		t.Fatal(err)
	}
	rmToken(t, w2.data)
	err = cmdAdopt([]string{"-key", keyFile, "-data", w2.data, "-mdns", "0", "-host", "203.0.113.52", "-config", "n2.json",
		"-catalog", w2.catalog})
	if !errors.Is(err, fleet.ErrManual) || !strings.Contains(err.Error(), "-primary-done") ||
		slices.Contains(w2.node.Events(), "push config") {
		t.Fatal(err, w2.node.Events())
	}
}
