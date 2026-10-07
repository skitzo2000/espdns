package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/rolling"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The CLI's dry run of a zones rollout says what each node would stop serving, from the
// same code as the Push page (rolling.ZonesNote); a node where a zone would be both hosted
// and a forward zone (its /status forward_zones) is refused before any node is touched. A
// config rollout that would make a zone a node hosts one of its forward zones is refused, and
// so is one putting a node on DHCP on a network in settings.json's no_dhcp.
func TestRolloutZoneSourcesAndDrops(t *testing.T) {
	data := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fl := fakenode.Fleet{}
	var hosts []string
	for i := range 2 {
		n := fakenode.New(fmt.Sprintf("n%d", i), [6]byte{2, 0, 0, 0, 0, byte(i + 1)}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(k))
		srv := httptest.NewServer(n)
		t.Cleanup(srv.Close)
		n.Addr = strings.TrimPrefix(srv.URL, "http://")
		fl[n.Addr] = n
		hosts = append(hosts, n.Addr)
		if _, err := pins.Open(data).Pin(n.ID(), n.Addr); err != nil { // adopted
			t.Fatal(err)
		}
	}
	a, b := hosts[0], hosts[1]
	if err := settings.Save(settings.Path(data), settings.Settings{Nodes: hosts, NoDHCP: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	zone := func(name string) []byte {
		return []byte("$ORIGIN " + name + ".\n$TTL 300\n@ IN SOA ns." + name + ". admin." + name + ". 1 3600 600 86400 300\n" +
			"@ IN NS ns." + name + ".\nns IN A 192.0.2.10\n")
	}
	put(t, filepath.Join(data, "zones/home.example.zone"), zone("home.example"))
	put(t, filepath.Join(data, "zones/lab.example.zone"), zone("lab.example"))
	var logs []string
	logf := func(f string, args ...any) { logs = append(logs, fmt.Sprintf(f, args...)); t.Logf(f, args...) }
	client := &fleet.Client{DNS: fl, PeerDNS: fl, Poll: time.Millisecond, Logf: logf,
		Pusher: &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(data)}}
	ctx := context.Background()
	run := func(dry bool, args ...string) (fleet.Result, error) {
		t.Helper()
		args = append([]string{"-key", "-", "-data", data, "-mdns", "0", "-host", a + "," + b, "-no-dns-checks"}, args...)
		if dry {
			args = append(args, "-dry-run")
		}
		req, _, err := rolloutRequest(args)
		if err != nil {
			t.Fatal(err)
		}
		bt, err := rolling.Build(ctx, client, req, logf)
		if err != nil {
			return fleet.Result{}, err
		}
		bt.Plan.Soak = 0
		return client.Rollout(ctx, bt.Plan, bt.Change)
	}
	both := []string{"-kind", "zones", "-zone", filepath.Join(data, "zones/home.example.zone"), "-zone", filepath.Join(data, "zones/lab.example.zone")}
	// Both nodes serve both zones.
	if _, err := run(false, both...); err != nil {
		t.Fatal(err)
	}
	logs = nil
	if _, err := run(true, "-kind", "zones", "-zone", filepath.Join(data, "zones/home.example.zone")); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if !strings.Contains(strings.Join(logs, "\n"), h+": would push zones now: it stops serving lab.example") {
			t.Errorf("%s: no drop said:\n%s", h, strings.Join(logs, "\n"))
		}
	}
	// A forward zone in b's /status: refused, nothing touched.
	fl[b].Do(func(n *fakenode.Node) {
		n.Forward = []nodecfg.ForwardZone{{Zone: "lab.example", Forwarder: "192.0.2.53"}}
	})
	before := len(fl[a].Events())
	if res, err := run(true, both...); err == nil || !strings.Contains(err.Error(), "lab.example is both a hosted zone and a forward zone of "+b) ||
		len(res.Left) != 2 || len(fl[a].Events()) != before {
		t.Errorf("forward zone: %v %+v", err, res)
	}
	fl[b].Do(func(n *fakenode.Node) { n.Forward = nil })
	// A config making lab.example (hosted on b) a forward zone: refused for b.
	put(t, filepath.Join(configs.Path(data), "n0.json"), []byte(`{"name":"n0","forwarders":["9.9.9.9"]}`))
	put(t, filepath.Join(configs.Path(data), "n1.json"),
		[]byte(`{"name":"n1","forwarders":["9.9.9.9"],"forward_zones":[{"zone":"lab.example","forwarder":"192.0.2.53"}]}`))
	cfgArgs := []string{"-kind", "config", "-config", a + "=n0.json", "-config", b + "=n1.json"}
	if _, err := run(true, cfgArgs...); err == nil || !strings.Contains(err.Error(), "makes lab.example a forward zone of "+b) {
		t.Errorf("config forward zone: %v", err)
	}
	// DHCP on a no_dhcp network (the fake nodes are on 127.0.0.1): refused.
	put(t, filepath.Join(configs.Path(data), "n1.json"), []byte(`{"name":"n1","forwarders":["9.9.9.9"],"network":{"address":"dhcp"}}`))
	if _, err := run(true, cfgArgs...); err == nil || !strings.Contains(err.Error(), "no DHCP server") {
		t.Errorf("config dhcp: %v", err)
	}
}
