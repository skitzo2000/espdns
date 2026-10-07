package configs

import (
	"fmt"
	"net/netip"

	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Addressing is what a config's address is checked against for the node it goes to
// (AddressRefusal): the deployment's settings, the other nodes known, and the network.
type Addressing struct {
	// Settings: its "no_dhcp" networks, its nodes and DNS peers.
	Settings settings.Settings
	// Known are other nodes' addresses besides settings.json's (found over mDNS, -peer).
	Known []string
	// Free, if set, asks the network whether an address is free for the node: nothing but
	// the node itself answers there (fleet.Client.AddressFree, adoption's check). nil: the
	// network isn't asked (a check that must not wait on it).
	Free func(addr string) error
}

// AddressRefusal is why the config can't go to the node at host (nil if it can), whose
// /status is st (nil if unread), for its address, as adoption checks one:
//   - "dhcp" for a node on a network in settings.json's "no_dhcp" (by host, or the address
//     the node reports): a node there gets a static address, never DHCP;
//   - a move onto an address another node or a DNS peer is known by (settings.json, Known),
//     even while that one is off: the wrong node's config, picked by mistake, would put two
//     hosts on one address;
//   - a move onto an address something answers on (Free).
//
// The CLI's espdns config (a push, and -check -host), the Configs page's check and its push
// job all ask it, so they refuse the same configs.
func (s Spec) AddressRefusal(a Addressing, st *release.NodeStatus) error {
	if n := s.Config.Network; n != nil && n.Address == "dhcp" {
		on := []string{hostOnly(s.Host)}
		if st != nil {
			on = append(on, hostOnly(st.IP))
			if st.Config != nil {
				if p, err := netip.ParsePrefix(st.Config.IP); err == nil {
					on = append(on, p.Addr().String())
				}
			}
		}
		for _, h := range on {
			ip, err := netip.ParseAddr(h)
			if err != nil {
				continue
			}
			if p, ok := a.Settings.NoDHCPAt(ip); ok {
				return fmt.Errorf("%s puts %s on DHCP, but %s is on %s, which has no DHCP server (settings.json, no_dhcp): "+
					"a node there gets a static address (\"network\": {\"address\": \"a.b.c.d/nn\", \"gateway\": ...})",
					s.Path, s.Host, ip, p)
			}
		}
	}
	to, ok := s.Moves()
	if !ok || st != nil && runsOn(*st, to) {
		// Not a move, or the node is reached by a name or another address but runs on this
		// one already (its /status): its own address isn't taken.
		return nil
	}
	others := append(append(append([]string{}, a.Settings.Nodes...), a.Settings.DNSPeers...), a.Known...)
	for _, o := range others {
		if o != s.Host && hostOnly(o) != hostOnly(s.Host) && hostOnly(o) == to.String() {
			return fmt.Errorf("%s moves %s to %s, which is %s's address: is it the config of that node? "+
				"(a node moves only to a free address)", s.Path, s.Host, to, o)
		}
	}
	if a.Free != nil {
		if err := a.Free(to.String()); err != nil {
			return fmt.Errorf("%s moves %s to %s, which isn't free: %w (a node moves only to a free address)", s.Path, s.Host, to, err)
		}
	}
	return nil
}

// runsOn says whether the node, whose /status is st, runs on addr: the address it reports
// (ip), or the static one its config gives it.
func runsOn(st release.NodeStatus, addr netip.Addr) bool {
	if a, err := netip.ParseAddr(hostOnly(st.IP)); err == nil && a == addr {
		return true
	}
	if st.Config != nil {
		if p, err := netip.ParsePrefix(st.Config.IP); err == nil && p.Addr() == addr {
			return true
		}
	}
	return false
}
