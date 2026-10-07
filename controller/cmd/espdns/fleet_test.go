package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

func TestHostList(t *testing.T) {
	var l hostList
	l.Set("a, b")
	l.Set("b,c")
	if !slices.Equal(l, hostList{"a", "b", "c"}) {
		t.Fatal(l)
	}
}

// A rolling config goes to the nodes it names; one that moves a node to another address
// goes through espdns config instead, which confirms it there.
func TestConfigPayloads(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o644)
		return p
	}
	same := write("a.json", `{"name":"a","network":{"address":"192.0.2.10/24","gateway":"192.0.2.1"}}`)
	moves := write("b.json", `{"name":"b","network":{"address":"192.0.2.99/24","gateway":"192.0.2.1"}}`)
	live := write("c.json", `{"name":"c"}`)
	f, _, err := configPayloads([]string{"192.0.2.10=" + same, "192.0.2.11=" + live}, []string{"192.0.2.10", "192.0.2.11"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := f(context.Background(), "192.0.2.11", release.NodeStatus{}); err != nil || !strings.Contains(string(b), `"c"`) {
		t.Fatal(string(b), err)
	}
	if _, _, err := configPayloads([]string{"192.0.2.11=" + moves}, []string{"192.0.2.11"}, "", ""); err == nil ||
		!strings.Contains(err.Error(), "espdns config") {
		t.Fatal(err)
	}
	if _, _, err := configPayloads([]string{"192.0.2.10=" + same}, []string{"192.0.2.10", "192.0.2.11"}, "", ""); err == nil {
		t.Fatal("a node without a config accepted")
	}
	if _, _, err := configPayloads([]string{live}, []string{"192.0.2.10", "192.0.2.11"}, "", ""); err == nil {
		t.Fatal("a bare file for two nodes accepted")
	}
}

// A config without a network is refused for a node whose address comes from its pushed
// config: it would drop the node off that address. A node on its board's or built-in
// address takes it, and a config with the network goes through either way.
func TestConfigPayloadsKeepAddress(t *testing.T) {
	dir := t.TempDir()
	noNet := filepath.Join(dir, "nonet.json")
	withNet := filepath.Join(dir, "net.json")
	os.WriteFile(noNet, []byte(`{"name":"a"}`), 0o644)
	os.WriteFile(withNet, []byte(`{"name":"a","network":{"address":"192.0.2.10/24","gateway":"192.0.2.1"}}`), 0o644)
	st := func(from string) release.NodeStatus {
		return release.NodeStatus{Config: &release.ConfigStatus{Source: "node", Address: "static", AddressFrom: from,
			IP: "192.0.2.10/24", Gateway: "192.0.2.1"}}
	}
	ctx := context.Background()
	f, _, err := configPayloads([]string{"192.0.2.10=" + noNet}, []string{"192.0.2.10"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f(ctx, "192.0.2.10", st("config"))
	if err == nil || !strings.Contains(err.Error(), "drop it off") || !strings.Contains(err.Error(), noNet) ||
		!strings.Contains(err.Error(), `"network": {"address": "192.0.2.10/24", "gateway": "192.0.2.1"}`) {
		t.Fatalf("config without network for a node addressed by its config: %v", err)
	}
	dhcp := st("config")
	dhcp.Config.Address, dhcp.Config.IP, dhcp.Config.Gateway = "dhcp", "", ""
	if _, err := f(ctx, "192.0.2.10", dhcp); err == nil || !strings.Contains(err.Error(), `"address": "dhcp"`) {
		t.Fatalf("on DHCP from its config: %v", err)
	}
	for _, s := range []release.NodeStatus{st("board"), st("firmware"), st(""), {}} {
		if b, err := f(ctx, "192.0.2.10", s); err != nil || len(b) == 0 {
			t.Fatalf("address from %+v: %v", s.Config, err)
		}
	}
	f, _, err = configPayloads([]string{"192.0.2.10=" + withNet}, []string{"192.0.2.10"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := f(ctx, "192.0.2.10", st("config")); err != nil || !strings.Contains(string(b), "192.0.2.10") {
		t.Fatalf("config with its network: %v", err)
	}
}

// A config that turns services on or off is refused, before any node is touched, for a node
// whose firmware has no services: that firmware refuses it. Other configs still go.
func TestConfigPayloadsServices(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	newer := release.NodeStatus{Services: []release.ServiceStatus{{Name: "dns", State: "running"}}}
	for body, switches := range map[string]bool{
		`{"name":"a"}`:                                  false,
		`{"forwarders":["9.9.9.9"]}`:                    false,
		`{"blocking":{"ttl":30}}`:                       false,
		`{"forwarders":[]}`:                             true,
		`{"hosted":{"enabled":true}}`:                   true,
		`{"blocking":{"enabled":true,"answer":"null"}}`: true,
	} {
		p := filepath.Join(dir, "a.json")
		os.WriteFile(p, []byte(body), 0o644)
		f, _, err := configPayloads([]string{"192.0.2.10=" + p}, []string{"192.0.2.10"}, "", "")
		if err != nil {
			t.Fatal(body, err)
		}
		if _, err := f(ctx, "192.0.2.10", newer); err != nil {
			t.Fatalf("%s on firmware with services: %v", body, err)
		}
		_, err = f(ctx, "192.0.2.10", release.NodeStatus{})
		if switches != (err != nil) || switches && !strings.Contains(err.Error(), "update its firmware first") {
			t.Fatalf("%s on firmware from before services: %v", body, err)
		}
	}
}

// A config with "cpu" is refused for a node whose firmware has no clock scaling (no /status
// "cpu"): that firmware refuses the key.
func TestConfigPayloadsCPU(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	newer := release.NodeStatus{CPU: &release.CPUStatus{PM: true}}
	for body, sets := range map[string]bool{
		`{"name":"a"}`:          false,
		`{"cpu":{}}`:            true,
		`{"cpu":{"dfs":false}}`: true,
	} {
		p := filepath.Join(dir, "a.json")
		os.WriteFile(p, []byte(body), 0o644)
		f, _, err := configPayloads([]string{"192.0.2.10=" + p}, []string{"192.0.2.10"}, "", "")
		if err != nil {
			t.Fatal(body, err)
		}
		if _, err := f(ctx, "192.0.2.10", newer); err != nil {
			t.Fatalf("%s on firmware with clock scaling: %v", body, err)
		}
		_, err = f(ctx, "192.0.2.10", release.NodeStatus{})
		if sets != (err != nil) || sets && !strings.Contains(err.Error(), "update its firmware first") {
			t.Fatalf("%s on firmware from before clock scaling: %v", body, err)
		}
	}
}

// DNS peers come from -dns-peer, else the settings' "dns_peers"; -no-dns-peers drops those.
func TestDNSPeerSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"nodes":["198.51.100.2"],"dns_peers":["198.51.100.254"],"dns_peer_zones":["home.example"]}`), 0o644)
	parse := func(args ...string) []string {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		d := addDNSPeerFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		ps, err := d.peers(path)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range ps {
			out = append(out, p.Addr+" "+strings.Join(p.Zones, ","))
		}
		return out
	}
	if got := parse(); !slices.Equal(got, []string{"198.51.100.254 home.example"}) {
		t.Fatal(got)
	}
	if got := parse("-dns-peer", "198.51.100.253", "-dns-peer-zone", "z.example"); !slices.Equal(got, []string{"198.51.100.253 z.example"}) {
		t.Fatal(got)
	}
	if got := parse("-no-dns-peers"); len(got) != 0 {
		t.Fatal(got)
	}
}
