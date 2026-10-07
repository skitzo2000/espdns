package fleet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Adopt is one node joining the deployment (docs/design.md, Adoption and addressing). The
// node is found where it already is, on a static address: its board's default, the one it
// was flashed with, or its node config's. No DHCP lease is involved: a node never asks for
// one on its own. Adopt puts the address in the node's config, which owns it from then on.
type Adopt struct {
	Host string // the node's address now (discover, or the address it was flashed with)
	ID   string // the node ID expected at Host; empty: whatever node answers there
	// Address is the node's static address, with the prefix length; zero: the static
	// address it runs on now (its /status), kept.
	Address netip.Prefix
	// Gateway goes with Address; zero: the node's gateway now, if it is in Address's network.
	Gateway netip.Addr
	// DHCP: the config asks for DHCP instead, for a network with a DHCP server (never
	// one in settings.json's no_dhcp). The node is then expected back at Host, which that server must
	// reserve for its MAC: Reserved says it does. Without it Adopt says what to reserve and
	// stops with ErrReservation.
	DHCP     bool
	Reserved bool
	// AskReserved, if set and Reserved isn't, asks whether the reservation is made.
	AskReserved func(addr, mac string) bool
	// Config is the node's config; its network is set from Address and Gateway (or DHCP).
	Config *nodecfg.Config
	// Identify flickers the node's LED for this long first, to match it to the board.
	Identify time.Duration
	// Primary is the zone primary whose allow lists step 4 changes (internal/primary). One
	// that isn't reached from here (Ready fails: a manual kind, no address or no token), or
	// nil (any primary): Adopt says what to change by hand, and goes on only with ManualDone
	// (a dry run always goes on).
	Primary primary.Primary
	// ManualDone: the changes step 4 names were made by hand on the primary (the CLI's
	// -primary-done, the controller's "I've made the changes").
	ManualDone bool
	// Check, if set, checks the config with its network set from the address, against the
	// node's /status, before anything is changed (internal/configs: the editor's and a
	// config rollout's checks).
	Check func(cfg *nodecfg.Config, st release.NodeStatus) error
	// Step, if set, hears each step as it starts (2 to 7), for the controller to show.
	Step func(n int, what string)
	// Resolved, if set, hears the address the node is adopted on (step 3; for DHCP, the
	// one it is found on).
	Resolved func(addr string)
	// Mask, if set, hides what the config payload holds that no log may (its Wi-Fi
	// password), where a dry run shows it.
	Mask func([]byte) []byte
	// Peers are the other adopted nodes, for the clients' DNS list (step 7) and, for a node
	// already adopted (in service), the rule before it is moved.
	Peers []string
	// DNSPeers are as in Plan: for a node already adopted, they count for the rule.
	DNSPeers []DNSPeer
	// AllowSingle and Force are as in Plan, for a node already adopted.
	AllowSingle, Force bool
	// DryRun does every check and says what each step would do; it pushes nothing.
	DryRun bool
	// ConfirmWait bounds step 6; 0: the node's trial window and 30 s.
	ConfirmWait time.Duration
	Checks      Checks
}

// AdoptResult is what an adoption did: the node, the address it is confirmed on, and the
// config it runs (seq and payload), to record as the config pushed to it.
type AdoptResult struct {
	NodeID  string
	Addr    string
	Seq     uint64
	Payload []byte
	// Servers are the addresses to hand out as the clients' DNS servers (step 7), once two
	// nodes are adopted.
	Servers []string
}

// ErrManual: the zone primary isn't changed from here (a manual kind, or no API address or
// token), and its lists aren't confirmed changed by hand.
var ErrManual = errors.New("the zone primary's allow lists aren't changed from here, " +
	"so make the changes above by hand on the primary, then confirm they are done")

// ErrReservation: a config on DHCP needs the address reserved first.
var ErrReservation = errors.New("a config on DHCP needs the node's address reserved in the DHCP server first, then adopt with it reserved")

// Adopt runs the adoption steps for one node (AdoptNode, without its result).
func (c *Client) Adopt(ctx context.Context, a Adopt) error {
	_, err := c.AdoptNode(ctx, a)
	return err
}

// AdoptNode runs the adoption steps for one node. Steps 0 (flash, with its address) and 1
// (first boot) are the node's own; this is 2 to 7. The result is set once the node is
// confirmed (not by a dry run).
func (c *Client) AdoptNode(ctx context.Context, a Adopt) (AdoptResult, error) {
	var res AdoptResult
	err := c.adopt(ctx, a, &res)
	return res, err
}

func (c *Client) adopt(ctx context.Context, a Adopt, res *AdoptResult) error {
	if a.DHCP && a.Address.IsValid() {
		return errors.New("a static address or DHCP, not both")
	}
	if a.Address.IsValid() && !a.Address.Addr().Is4() {
		return errors.New("need an IPv4 address with its prefix length (192.0.2.53/24)")
	}
	if a.Config == nil {
		a.Config = &nodecfg.Config{}
	}
	step := func(n int, what string) {
		if a.Step != nil {
			a.Step(n, what)
		}
	}

	// 2. Discovery: the node, as it is now.
	step(2, "reading the node at "+a.Host)
	st, err := c.Status(ctx, a.Host)
	if err != nil {
		return fmt.Errorf("2. the node at %s: %w", a.Host, err)
	}
	if a.ID != "" && !strings.EqualFold(st.NodeID, a.ID) {
		return fmt.Errorf("2. %s is node %s, not %s", a.Host, st.NodeID, a.ID)
	}
	mac := st.Net.MAC
	if mac == "" {
		mac = st.NodeID
	}
	c.logf("2. node %s at %s: board %s, chip image %s, firmware %s %s, %s, MAC %s", st.NodeID, a.Host, st.Board,
		st.Image, st.Project, st.Version, st.Net.Kind, mac)
	if _, ok := st.Seq[release.Config.String()]; !ok {
		err := errors.New("its firmware takes no node configs: update it first (espdns rollout -kind firmware)")
		if !a.DryRun {
			return fmt.Errorf("2. %w", err)
		}
		c.logf("   %v", err)
	}
	// A node already adopted is one clients use: it moves (and reboots) only under the
	// rule, as any other change (docs/design.md, Principles).
	inService := st.Config != nil && st.Config.Source == "node"
	if !inService && st.Config != nil && st.Seq[release.Config.String()] > 0 {
		c.logf("   note: it took config seq %d before and runs its board's settings now (%s): if it is a node in "+
			"service whose config no longer loads, this gives it the config and address here instead",
			st.Seq[release.Config.String()], st.Config.Error)
	}
	// The node's ID is pinned to its address here, as it answers now: every release after
	// this is signed for that ID, whatever a /status says later (internal/pins).
	if !a.DryRun {
		if err := c.pinAdopted(st.NodeID, a.Host); err != nil {
			return fmt.Errorf("2. %w", err)
		}
	}
	if a.Identify > 0 {
		if a.DryRun {
			c.logf("   would flicker its LED for %v", a.Identify)
		} else if r, err := c.push(ctx, a.Host, release.Control, release.IdentifyPayload(a.Identify)); err != nil {
			return fmt.Errorf("2. identify: %w", err)
		} else {
			c.logf("   %s", r)
		}
	}

	// 3. Address: the one it has (board default, flashed, or config), or the one given.
	step(3, "the address")
	if err := a.Resolve(st); err != nil {
		return fmt.Errorf("3. %w", err)
	}
	addr := a.Host
	if a.DHCP {
		c.logf("3. DHCP: in the DHCP server, reserve %s for MAC %s (%s)", addr, mac, st.Net.Hostname)
		a.Config.Network = &nodecfg.Network{Address: "dhcp"}
	} else {
		addr = a.Address.Addr().String()
		c.logf("3. static address %s, gateway %s (%s)", a.Address, a.Gateway, a.AddressHow(st))
		a.Config.Network = &nodecfg.Network{Address: a.Address.String(), Gateway: a.Gateway.String()}
	}
	if a.Resolved != nil {
		a.Resolved(addr)
	}
	if inService {
		c.logf("   it is already in service (config seq %d): this moves it under the rule", st.Config.Seq)
	}
	if a.Check != nil {
		if err := a.Check(a.Config, st); err != nil {
			return fmt.Errorf("3. the config, with this address, for this node: %w", err)
		}
	}
	if addr != a.Host {
		if err := c.AddressFree(ctx, addr, st.NodeID, st.Net.MAC); err != nil {
			return fmt.Errorf("3. %w", err)
		}
	}
	payload, err := a.Config.Payload()
	if err != nil {
		return fmt.Errorf("5. the config: %w", err)
	}
	if a.DHCP {
		if !a.Reserved && a.AskReserved != nil && !a.DryRun {
			a.Reserved = a.AskReserved(addr, mac)
		}
		if !a.Reserved {
			if !a.DryRun {
				return ErrReservation
			}
			c.logf("   (dry run: going on as if it were reserved)")
		}
	}

	// 4. Allow list on the zone primary, for each secondary zone the node carries.
	step(4, "the zone primary's allow lists")
	if s := a.Config.Secondary; s != nil && s.Zones != nil && len(*s.Zones) > 0 {
		driven := a.Primary != nil && a.Primary.Ready() == nil
		if !driven {
			for _, z := range *s.Zones {
				c.logf("4. by hand: %s", ManualSteps(a.Primary, s.Primary, z, addr))
			}
			switch {
			case a.DryRun:
				c.logf("   (dry run: the adoption itself goes on only once these are confirmed done)")
			case !a.ManualDone:
				return fmt.Errorf("4. %w", ErrManual)
			default:
				c.logf("   confirmed done by hand")
			}
		}
		for _, z := range *s.Zones {
			if !driven {
				break
			}
			c.logf("4. %s: allowing %s to transfer it and get its NOTIFYs", z, addr)
			if err := a.Primary.Allow(ctx, z, addr); err != nil {
				return fmt.Errorf("4. %s: %w", z, err)
			}
		}
	} else {
		c.logf("4. no secondary zones: nothing to allow on a primary")
	}

	// 5. Config, with the address, to the node's current address.
	step(5, "the config, to "+a.Host)
	if inService {
		p := Plan{Peers: a.Peers, DNSPeers: a.DNSPeers, AllowSingle: a.AllowSingle, Force: a.Force, Checks: a.Checks}
		if err := c.gate(ctx, p, a.Host, true); err != nil {
			return fmt.Errorf("5. %s is in service: not moved: %w", a.Host, err)
		}
	}
	if a.DryRun {
		shown := payload
		if a.Mask != nil {
			shown = a.Mask(payload)
		}
		c.logf("5. would push this config to %s:\n%s", a.Host, shown)
		c.logf("6. would confirm it on %s; 7. then list the clients' DNS servers. Dry run: nothing pushed.", addr)
		return nil
	}
	if c.Pusher == nil {
		return errors.New("no release key to sign with")
	}
	r, err := c.Pusher.PushRelease(ctx, a.Host, release.Config, payload)
	if err != nil {
		return fmt.Errorf("5. %w", err)
	}
	c.logf("5. %s: %s", a.Host, r.Reply)
	if pending, _ := c.RebootPending(ctx, a.Host, r.Node); pending {
		// Not in service yet: no other node to wait for.
		if inService {
			// The push took a while: the rule again, right before it goes down.
			p := Plan{Peers: a.Peers, DNSPeers: a.DNSPeers, AllowSingle: a.AllowSingle, Force: a.Force, Checks: a.Checks}
			if err := c.gate(ctx, p, a.Host, true); err != nil {
				return fmt.Errorf("5. %s waits for a reboot, not rebooted: %w", a.Host, err)
			}
		}
		if err := c.sendReboot(ctx, a.Host, true); err != nil {
			return fmt.Errorf("5. %w", err)
		}
	}

	// 6. Confirm on the address: a config that moves the node is kept only if it is reached
	// there (one that keeps the address it had applies without a trial).
	step(6, "confirming it on "+addr)
	wait := a.ConfirmWait
	if wait == 0 {
		wait = TrialWindow + 30*time.Second
	}
	locate := func(context.Context) []string { return []string{addr, a.Host} }
	cs, at, err := c.ConfirmConfig(ctx, locate, st.NodeID, r.Seq, wait)
	if err != nil {
		return fmt.Errorf("6. %w", err)
	}
	if at != addr {
		return fmt.Errorf("6. the node kept config seq %d but answers on %s, not %s", cs.Seq, at, addr)
	}
	p := Plan{Checks: a.Checks, ConfirmWait: wait}
	if err := c.verify(ctx, p, addr, nil, nil); err != nil {
		return fmt.Errorf("6. %s: %w", addr, err)
	}
	c.logf("6. node %s confirmed on %s (config seq %d, %s address)", st.NodeID, addr, cs.Seq, cs.Address)
	*res = AdoptResult{NodeID: st.NodeID, Addr: addr, Seq: cs.Seq, Payload: payload}

	// 7. The clients' DNS list, once two nodes are adopted.
	step(7, "the clients' DNS servers")
	servers := []string{addr}
	for _, h := range a.Peers {
		if h != addr && !slices.Contains(servers, h) && c.Answers(ctx, h) == nil {
			servers = append(servers, h)
		}
	}
	if len(servers) >= 2 {
		res.Servers = servers
		c.logf("7. hand out %s as the clients' DNS servers (the router's DHCP DNS setting, on networks with DHCP)",
			strings.Join(servers, ", "))
	} else {
		c.logf("7. adopt a second node, then hand out both as the clients' DNS servers")
	}
	return nil
}

// ManualSteps is the change to make by hand on the zone primary (at the address
// primaryAddr, as the node config names it) for addr to transfer zone and get its NOTIFYs,
// in p's terms; p nil: any primary's.
func ManualSteps(p primary.Primary, primaryAddr, zone, addr string) string {
	if p == nil {
		return primary.ManualGeneric(primaryAddr, zone, addr)
	}
	return p.Manual(primaryAddr, zone, addr)
}

// Resolve fills in Address and Gateway from what the node, whose /status is st, runs on
// now where they aren't given, and checks them (step 3).
func (a *Adopt) Resolve(st release.NodeStatus) error {
	if a.DHCP {
		return nil
	}
	cur, curOK := currentAddress(st)
	var curGW netip.Addr
	if curOK {
		curGW, _ = netip.ParseAddr(st.Config.Gateway)
	}
	if !a.Address.IsValid() {
		if !curOK {
			return errors.New("the node reports no static address it runs on (no address, DHCP, or firmware " +
				"from before this was reported): give the address")
		}
		a.Address = cur
	}
	if !a.Gateway.IsValid() {
		if !curGW.IsValid() || !a.Address.Masked().Contains(curGW) {
			return fmt.Errorf("need the gateway for %s", a.Address)
		}
		a.Gateway = curGW
	}
	n := nodecfg.Network{Address: a.Address.String(), Gateway: a.Gateway.String()}
	return n.Check()
}

// AddressFree checks that nothing but the node itself (self, its ID; macs, its interface's)
// is at addr: no other node, nothing else that answers HTTP, no host that refuses the
// connection, no DNS server, and, on the controller's own network, nothing that answered
// ARP for it (a host that drops HTTP and DNS still answers that). With no DHCP server
// handing addresses out, an address given by hand to two devices is the collision to catch
// before the node moves onto it: adoption asks it, and so does a config that moves a node
// (internal/configs, AddressRefusal).
func (c *Client) AddressFree(ctx context.Context, addr, self string, macs ...string) error {
	other, err := c.Status(ctx, addr)
	if err == nil {
		if strings.EqualFold(other.NodeID, self) {
			return nil
		}
		return fmt.Errorf("%s is in use by node %s", addr, other.NodeID)
	}
	var ue *url.Error
	if !errors.As(err, &ue) { // a reply, but not a node's /status
		return fmt.Errorf("%s is in use: something there answers HTTP (%v)", addr, err)
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("%s is in use: a host there refuses connections", addr)
	}
	if c.Answers(ctx, addr) == nil {
		return fmt.Errorf("%s is in use: a DNS server answers there", addr)
	}
	// The tries above made the kernel ask ARP for addr, if it is on a network it is on.
	if mac := arpMAC(arpTable, addr); mac != "" && !slices.ContainsFunc(append([]string{self}, macs...),
		func(m string) bool { return strings.EqualFold(m, mac) }) {
		return fmt.Errorf("%s is in use: a host there (MAC %s) answers ARP, though not HTTP or DNS", addr, mac)
	}
	return nil
}

// arpTable is the kernel's ARP table (Linux; the controller and the CLI run with the host's
// network). Tests point it elsewhere.
var arpTable = "/proc/net/arp"

// arpMAC is the hardware address the ARP table has for addr, complete (it answered), or "".
// No table (another system, or another network namespace) is no answer.
func arpMAC(table, addr string) string {
	b, err := os.ReadFile(table)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		// IP address, HW type, Flags, HW address, Mask, Device
		if len(f) < 4 || f[0] != addr {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 || f[3] == "00:00:00:00:00:00" {
			continue
		}
		return f[3]
	}
	return ""
}

// AddressHow says where the address step 3 settled on comes from, for st's node: kept
// (and from which layer), or new.
func (a *Adopt) AddressHow(st release.NodeStatus) string {
	if a.DHCP {
		return "dhcp"
	}
	if cur, ok := currentAddress(st); ok && cur == a.Address {
		return "kept, from its " + st.Config.AddressFrom
	}
	return "new"
}

// currentAddress is the static address the node runs on, as its /status reports it.
func currentAddress(st release.NodeStatus) (netip.Prefix, bool) {
	if st.Config == nil || st.Config.Address != "static" || st.Config.IP == "" {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(st.Config.IP)
	return p, err == nil && p.Addr().Is4()
}

// pinAdopted pins node id to host for its adoption. An address another node is pinned to
// is refused: that is for espdns pin to change, knowing which node is there.
func (c *Client) pinAdopted(id, host string) error {
	if c.Pusher == nil || c.Pusher.Pins == nil {
		return errors.New("no release key and record of the nodes to sign with")
	}
	cur, err := c.Pusher.Pins.Pinned(host)
	switch {
	case errors.Is(err, pins.ErrNotPinned):
	case err != nil:
		return err
	case !strings.EqualFold(cur, id):
		return fmt.Errorf("%s answers as node %s, but node %s is pinned there: if its board was replaced, "+
			"pin the new one first (espdns pin -host %s -node %s)", host, id, cur, host, id)
	}
	if _, err := c.Pusher.Pins.Pin(id, host); err != nil {
		return err
	}
	c.logf("   node %s pinned to %s: releases are signed for it there", id, host)
	return nil
}

// push sends one release and returns the node's reply.
func (c *Client) push(ctx context.Context, host string, kind release.Kind, payload []byte) (string, error) {
	if c.Pusher == nil {
		return "", errors.New("no release key to sign with")
	}
	return c.Pusher.Push(ctx, host, kind, payload)
}
