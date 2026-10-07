package configs

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

func spec(t *testing.T, host, text string) Spec {
	t.Helper()
	s, err := ParseSpec(host, "n.json", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A config's address for its node: no DHCP on a no_dhcp network (by the node's address or
// the one it reports), a move onto no address another node or DNS peer is known by, nor one
// the network says is taken.
func TestAddressRefusal(t *testing.T) {
	set := settings.Settings{Nodes: []string{"192.0.2.10", "192.0.2.11"}, DNSPeers: []string{"192.0.2.53"},
		NoDHCP: []string{"192.0.2.0/24"}}
	dhcp := `{"name":"n","network":{"address":"dhcp"}}`
	a := Addressing{Settings: set}
	if err := spec(t, "192.0.2.10", dhcp).AddressRefusal(a, nil); err == nil || !strings.Contains(err.Error(), "no DHCP server") {
		t.Errorf("dhcp on no_dhcp: %v", err)
	}
	// Reached by a name or elsewhere, but reporting an address there: refused too.
	st := release.NodeStatus{IP: "192.0.2.10", Config: &release.ConfigStatus{IP: "192.0.2.10/24"}}
	if err := spec(t, "node.example", dhcp).AddressRefusal(a, &st); err == nil || !strings.Contains(err.Error(), "192.0.2.0/24") {
		t.Errorf("dhcp by its /status: %v", err)
	}
	// Off the no_dhcp network: DHCP is the deployment's choice.
	if err := spec(t, "198.51.100.10", dhcp).AddressRefusal(a, nil); err != nil {
		t.Errorf("dhcp elsewhere: %v", err)
	}
	// A static address there is fine, and so is staying on its own.
	stay := `{"name":"n","network":{"address":"192.0.2.10/24","gateway":"192.0.2.1"}}`
	if err := spec(t, "192.0.2.10", stay).AddressRefusal(a, nil); err != nil {
		t.Errorf("static, the same: %v", err)
	}
	// Reached by a name, staying on the address it runs on (its /status): no move, so not
	// "another node's address", though settings.json lists it by that address.
	self := release.NodeStatus{IP: "192.0.2.10", Config: &release.ConfigStatus{IP: "192.0.2.10/24"}}
	a.Free = func(addr string) error { return errors.New("asked about its own address " + addr) }
	if err := spec(t, "dns1.example", stay).AddressRefusal(a, &self); err != nil {
		t.Errorf("its own address, by name: %v", err)
	}
	a.Free = nil
	// A move onto another node's, a DNS peer's or a found node's address.
	for _, to := range []string{"192.0.2.11", "192.0.2.53", "192.0.2.77"} {
		mv := `{"name":"n","network":{"address":"` + to + `/24","gateway":"192.0.2.1"}}`
		a := Addressing{Settings: set, Known: []string{"192.0.2.77:80"}}
		if err := spec(t, "192.0.2.10", mv).AddressRefusal(a, nil); err == nil || !strings.Contains(err.Error(), "'s address") {
			t.Errorf("move onto %s: %v", to, err)
		}
	}
	// A move onto a free one: the network asked (adoption's check), its answer kept.
	mv := `{"name":"n","network":{"address":"192.0.2.20/24","gateway":"192.0.2.1"}}`
	asked := ""
	a.Free = func(addr string) error { asked = addr; return nil }
	if err := spec(t, "192.0.2.10", mv).AddressRefusal(a, nil); err != nil || asked != "192.0.2.20" {
		t.Errorf("free move: %v (asked %q)", err, asked)
	}
	a.Free = func(string) error { return errors.New("192.0.2.20 is in use: a DNS server answers there") }
	if err := spec(t, "192.0.2.10", mv).AddressRefusal(a, nil); err == nil || !strings.Contains(err.Error(), "isn't free") {
		t.Errorf("taken move: %v", err)
	}
	// The editor's check says it per node, apart from a rollout's refusals.
	ck := Check{Name: "n.json", Text: []byte(dhcp), Host: "192.0.2.10", Status: &release.NodeStatus{}, Addressing: &Addressing{Settings: set}}
	if r := ck.Run(); r.OK || r.Node == nil || !strings.Contains(r.Node.Address, "no DHCP server") || r.Node.Refusal != "" {
		t.Errorf("check: %+v", r.Node)
	}
}

// A config that makes a zone the node serves as a hosted zone one of its forward or
// secondary zones is refused for that node, while its hosted zones stay on.
func TestHostedClash(t *testing.T) {
	var st release.NodeStatus
	json.Unmarshal([]byte(`{"hosted":{"state":"on","zones":[{"name":"home.example"}]}}`), &st)
	fwd := `{"name":"n","forward_zones":[{"zone":"Home.Example.","forwarder":"192.0.2.53"}]}`
	if err := spec(t, "192.0.2.10", fwd).Refusal(st, ""); err == nil || !strings.Contains(err.Error(), "home.example a forward zone") {
		t.Errorf("forward: %v", err)
	}
	sec := `{"name":"n","secondary":{"primary":"192.0.2.1","zones":["home.example"]}}`
	if err := spec(t, "192.0.2.10", sec).Refusal(st, ""); err == nil || !strings.Contains(err.Error(), "a secondary zone") {
		t.Errorf("secondary: %v", err)
	}
	// Hosted zones off in the config, another zone, or none hosted: nothing to clash with.
	for _, ok := range []string{
		`{"name":"n","hosted":{"enabled":false},"forward_zones":[{"zone":"home.example","forwarder":"192.0.2.53"}]}`,
		`{"name":"n","forward_zones":[{"zone":"corp.example","forwarder":"192.0.2.53"}]}`,
	} {
		st := st
		st.Services = []release.ServiceStatus{{Name: "hosted", State: "running"}}
		if err := spec(t, "192.0.2.10", ok).Refusal(st, ""); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if err := spec(t, "192.0.2.10", fwd).Refusal(release.NodeStatus{}, ""); err != nil {
		t.Errorf("nothing hosted: %v", err)
	}
}
