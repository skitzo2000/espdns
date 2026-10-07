package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The CLI's flags, as make fleet-rollout passes them, and the Push page's request for the
// same intent make the same request, and it builds into the same plan and the same change:
// the same nodes in the same order, the same peers and DNS peers, the same checks and soak,
// and for every node the same payload (or firmware). So the page runs the rollout the
// Makefile does, not a copy of it.
func TestCLIAndPushPageBuildTheSamePlan(t *testing.T) {
	data, catalog := t.TempDir(), t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	put(t, filepath.Join(catalog, "p4-ip101.json"), []byte(`{"name": "p4-ip101", "image": "esp32p4-rev1"}`))
	put(t, filepath.Join(catalog, "ws-s3-eth.json"), []byte(`{"name": "ws-s3-eth", "image": "esp32s3-octal"}`))
	fl := fakenode.Fleet{}
	var hosts []string
	for i, img := range []string{"esp32p4-rev1", "esp32s3-octal", "esp32p4-rev1"} {
		n := fakenode.New(fmt.Sprintf("n%d", i), [6]byte{2, 0, 0, 0, 0, byte(i + 1)}, img, "p4-ip101", release.PublicRaw(k))
		srv := httptest.NewServer(n)
		t.Cleanup(srv.Close)
		n.Addr = strings.TrimPrefix(srv.URL, "http://")
		fl[n.Addr] = n
		hosts = append(hosts, n.Addr)
	}
	a, b, c := hosts[0], hosts[1], hosts[2]
	// settings.json's canary: a rollout's when none is given, by both (CanaryFor).
	if err := settings.Save(settings.Path(data), settings.Settings{Nodes: hosts, DNSPeers: []string{"127.0.0.1:1053"},
		DNSPeerZones: []string{"home.example"}, Canary: c}); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(data, "firmware/builds/p4-ip101/dns2.bin"), fakenode.App("2", "0000000000000002"))
	put(t, filepath.Join(data, "firmware/builds/ws-s3-eth/dns2.bin"), fakenode.App("2", "0000000000000003"))
	put(t, filepath.Join(data, "firmware/images/esp32s3-octal/image.json"), []byte(`{"image": "esp32s3-octal"}`))
	put(t, filepath.Join(data, "firmware/images/esp32s3-octal/app.bin"), fakenode.App("4", "0000000000000004"))
	var es []blocklist.Entry
	for i := range 500 {
		es = append(es, blocklist.Entry{Name: fmt.Sprintf("ads%d.example.net", i)})
	}
	list, _, err := blocklist.Build(blocklist.Compile(es), blocklist.BuildOptions{Bits: 44, XorBits: 8, Keys: 1})
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(data, "lists/list.bin"), list)
	put(t, filepath.Join(data, "lists/must-resolve.txt"), []byte("example.org\n# a comment\nwikipedia.org\n"))
	put(t, filepath.Join(data, "zones/home.example.zone"), []byte("$ORIGIN home.example.\n$TTL 300\n"+
		"@ IN SOA ns.home.example. admin.home.example. 1 3600 600 86400 300\n@ IN NS ns.home.example.\nns IN A 192.0.2.10\n"))
	put(t, filepath.Join(data, "zones/lab.example.zone"), []byte("$ORIGIN lab.example.\n$TTL 300\n"+
		"@ IN SOA ns.lab.example. admin.lab.example. 1 3600 600 86400 300\n@ IN NS ns.lab.example.\nns IN A 192.0.2.11\n"))
	for i := range hosts {
		put(t, filepath.Join(configs.Path(data), fmt.Sprintf("n%d.json", i)), []byte(fmt.Sprintf(`{"name": "n%d", "forwarders": ["9.9.9.9"]}`, i)))
	}
	D := func(p string) string { return filepath.Join(data, p) }

	for _, tc := range []struct {
		name string
		cli  []string // what make fleet-rollout[-dry] passes for it (paths in the data directory)
		web  string   // what the Push page sends
	}{
		{"firmware, two boards' builds, canary, checks",
			[]string{"-kind", "firmware", "-key", "-", "-data", data, "-mdns", "0", "-host", a + "," + b + "," + c, "-canary", b,
				"-image", "esp32p4-rev1=" + D("firmware/builds/p4-ip101/dns2.bin"), "-image", "esp32s3-octal=" + D("firmware/builds/ws-s3-eth/dns2.bin"),
				"-check-blocked", "doubleclick.net", "-check-blocked", "ads.example", "-must-resolve", D("lists/must-resolve.txt"), "-dry-run"},
			`{"kind":"firmware","nodes":["` + a + `","` + b + `","` + c + `"],"canary":"` + b + `","firmware":["builds/p4-ip101","builds/ws-s3-eth"],
			  "check_blocked":["doubleclick.net","ads.example"],"must_resolve":"must-resolve.txt","dry_run":true}`},
		{"firmware, an exported chip image, a longer soak",
			[]string{"-kind", "firmware", "-key", "-", "-data", data, "-mdns", "0", "-host", b, "-canary", b, "-soak", "3m",
				"-image", D("firmware/images/esp32s3-octal")},
			`{"kind":"firmware","nodes":["` + b + `"],"canary":"` + b + `","soak_s":180,"firmware":["images/esp32s3-octal"]}`},
		{"config per node",
			[]string{"-kind", "config", "-key", "-", "-data", data, "-mdns", "0", "-host", c + "," + a,
				"-config", c + "=" + D("configs/n2.json"), "-config", a + "=" + D("configs/n0.json")},
			`{"kind":"config","nodes":["` + c + `","` + a + `"],"configs":{"` + a + `":"n0.json","` + c + `":"n2.json"}}`},
		{"blocklist, the canary second in NODES",
			[]string{"-kind", "blocklist", "-key", "-", "-data", data, "-mdns", "0", "-host", a + "," + b, "-canary", b,
				"-file", D("lists/list.bin"), "-check-blocked", "ads1.example.net", "-dry-run"},
			`{"kind":"blocklist","nodes":["` + a + `","` + b + `"],"canary":"` + b + `","file":"list.bin","check_blocked":["ads1.example.net"],"dry_run":true}`},
		{"blocklist, settings.json's canary (no -canary), the checks",
			[]string{"-kind", "blocklist", "-key", "-", "-data", data, "-mdns", "0", "-host", a + "," + b + "," + c,
				"-file", D("lists/list.bin"), "-check-blocked", "ads1.example.net", "-must-resolve", D("lists/must-resolve.txt"), "-dry-run"},
			`{"kind":"blocklist","nodes":["` + a + `","` + b + `","` + c + `"],"file":"list.bin","check_blocked":["ads1.example.net"],"must_resolve":"must-resolve.txt","dry_run":true}`},
		{"overrides",
			[]string{"-kind", "overrides", "-key", "-", "-data", data, "-mdns", "0", "-host", a, "-canary", a, "-file", D("lists/list.bin")},
			`{"kind":"overrides","nodes":["` + a + `"],"canary":"` + a + `","file":"list.bin"}`},
		{"zones",
			[]string{"-kind", "zones", "-key", "-", "-data", data, "-mdns", "0", "-host", a + "," + b + "," + c,
				"-zone", D("zones/home.example.zone"), "-zone", D("zones/lab.example.zone")},
			`{"kind":"zones","nodes":["` + a + `","` + b + `","` + c + `"],"zones":["home.example.zone","lab.example.zone"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliReq, _, err := rolloutRequest(append(tc.cli, "-catalog", catalog))
			if err != nil {
				t.Fatal(err)
			}
			w, err := rolling.ParseWeb([]byte(tc.web))
			if err != nil {
				t.Fatal(err)
			}
			webReq, err := w.Request(data, catalog)
			if err != nil {
				t.Fatal(err)
			}
			// The page's request reads each file once (Files); the CLI's when needed.
			if webReq.Files == nil {
				t.Fatal("the page's request has no Files")
			}
			if !reflect.DeepEqual(cliReq, func(r rolling.Request) rolling.Request { r.Files = nil; return r }(webReq)) {
				cj, _ := json.MarshalIndent(cliReq, "", " ")
				wj, _ := json.MarshalIndent(webReq, "", " ")
				t.Fatalf("requests differ:\nCLI %s\npage %s", cj, wj)
			}
			client := func() *fleet.Client {
				return &fleet.Client{DNS: fl, PeerDNS: fl, Poll: time.Millisecond, Logf: t.Logf}
			}
			ctx := context.Background()
			bc, err := rolling.Build(ctx, client(), cliReq, t.Logf)
			if err != nil {
				t.Fatal(err)
			}
			bw, err := rolling.Build(ctx, client(), webReq, t.Logf)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(bc.Plan, bw.Plan) {
				t.Errorf("plans differ:\nCLI  %+v\npage %+v", bc.Plan, bw.Plan)
			}
			// Without a canary given, settings.json's (one of the nodes changed) goes first.
			if cliReq.Canary == "" && slices.Contains(cliReq.Hosts, c) && (bc.Plan.Canary != c || bc.Plan.Order()[0] != c ||
				!slices.Equal(webReq.Order(), bc.Plan.Order())) {
				t.Errorf("canary %q, order %v / %v", bc.Plan.Canary, bc.Plan.Order(), webReq.Order())
			}
			// The same plan said the same way (a list's canary, soak and revert).
			if d := bw.Plan.Describe(bw.Change.Kind); !reflect.DeepEqual(bc.Plan.Describe(bc.Change.Kind), d) || len(d) == 0 {
				t.Errorf("plan descriptions differ: %q", d)
			}
			if bc.Change.Kind != bw.Change.Kind || bc.Change.Reinstall || bw.Change.Reinstall ||
				!reflect.DeepEqual(bc.Change.Firmware, bw.Change.Firmware) || !reflect.DeepEqual(bc.Specs, bw.Specs) {
				t.Errorf("changes differ:\nCLI  %+v\npage %+v", bc.Change, bw.Change)
			}
			// Every node's payload, from its /status, byte for byte.
			for _, h := range bc.Plan.Order() {
				st, err := client().Status(ctx, h)
				if err != nil {
					t.Fatal(err)
				}
				pc, plc, errc := bc.Change.Prepare(ctx, h, st)
				pw, plw, errw := bw.Change.Prepare(ctx, h, st)
				if string(pc) != string(pw) || plc != plw || fmt.Sprint(errc) != fmt.Sprint(errw) {
					t.Errorf("%s: payloads differ: %d/%d bytes, %q/%q, %v/%v", h, len(pc), len(pw), plc, plw, errc, errw)
				}
				if nc, nw := bc.Change.NoteFor(h, st), bw.Change.NoteFor(h, st); nc != nw {
					t.Errorf("%s: notes differ: %q / %q", h, nc, nw)
				}
			}
			// A zones push to a node that has one of the zones as a secondary zone: refused by
			// both, the same, before any node is touched.
			if tc.name == "zones" {
				fl[b].Do(func(n *fakenode.Node) { n.Secondary = []string{"lab.example"} })
				defer fl[b].Do(func(n *fakenode.Node) { n.Secondary = nil })
				st, err := client().Status(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				_, _, errc := bc.Change.Prepare(ctx, b, st)
				_, _, errw := bw.Change.Prepare(ctx, b, st)
				if errc == nil || fmt.Sprint(errc) != fmt.Sprint(errw) || !strings.Contains(errc.Error(), "a secondary zone of "+b) {
					t.Errorf("secondary zone: %v / %v", errc, errw)
				}
				before := len(fl[a].Events())
				dry := bc.Plan
				dry.DryRun = true
				res, err := client().Rollout(ctx, dry, bc.Change)
				if err == nil || !strings.Contains(err.Error(), "a secondary zone of "+b) || len(res.Left) != 3 || res.Failed != "" ||
					len(fl[a].Events()) != before {
					t.Errorf("rollout: %v %+v %v", err, res, fl[a].Events())
				}
			}
			// The plan as the Makefile means it: -mdns 0 counts the settings' nodes, its DNS
			// peers, the default checks and soak, and nothing loosened.
			p := bw.Plan
			if p.AllowSingle || p.Force || p.Checks.Off || len(p.DNSPeers) != 1 || p.DNSPeers[0].Addr != "127.0.0.1:1053" ||
				p.Checks.Forwarded[0] != "example.com" || p.Soak < time.Minute {
				t.Errorf("plan %+v", p)
			}
		})
	}
}
