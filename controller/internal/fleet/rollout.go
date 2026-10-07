package fleet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Firmware is one app image for a rolling firmware update.
type Firmware struct {
	Image string // the chip image it was built as (esp32p4-rev1, ...)
	Board string // for a node on firmware from before board definitions: the board it was built for
	App   []byte
	Desc  release.AppDesc
}

// Change is what a rolling push sends to each node.
type Change struct {
	Kind release.Kind // Firmware, Config, Zones, Blocklist or Overrides
	// Payload is the release for the node at host, whose /status is st. It is called for
	// every node before the first is touched, so a payload that can't be made for one node
	// stops the change before it starts. Not used for firmware.
	Payload func(ctx context.Context, host string, st release.NodeStatus) ([]byte, error)
	// Firmware is the app per chip image (by board name for a node from before chip images).
	Firmware []Firmware
	// Reinstall pushes firmware to a node that already runs the build.
	Reinstall bool
	// Note, if set, says what else the change does on the node at host, whose /status is
	// st, before it is touched ("" for nothing): a dry run logs it with what it would push,
	// and the Push page shows it per node (a zones push: the hosted zones it stops serving).
	Note func(host string, st release.NodeStatus) string
}

// NoteFor is the change's Note for the node, or "".
func (ch Change) NoteFor(host string, st release.NodeStatus) string {
	if ch.Note == nil {
		return ""
	}
	return ch.Note(host, st)
}

// isList: a blocklist or overrides, which a node can send back to the copy it had (the
// revert command): a list rollout soaks every node, watched, and reverts on a failure.
func (ch Change) isList() bool { return ch.Kind == release.Blocklist || ch.Kind == release.Overrides }

// mayReboot: kinds the node may apply with a reboot (docs/design.md, Signed releases).
func (ch Change) mayReboot() bool {
	return ch.Kind == release.Firmware || ch.Kind == release.Config || ch.Kind == release.Blocklist
}

// serviceFor is the node service that takes releases of kind (firmware/main/svc.h), or "".
func serviceFor(kind release.Kind) string {
	switch kind {
	case release.Blocklist, release.Overrides:
		return "blocking"
	case release.Zones:
		return "hosted"
	}
	return ""
}

// firmwareFor is the app for the node, by its chip image (or, before chip images, board).
func (ch Change) firmwareFor(st release.NodeStatus) (Firmware, bool) {
	for _, f := range ch.Firmware {
		if st.Image != "" && f.Image == st.Image || st.Image == "" && f.Board != "" && f.Board == st.Board {
			return f, true
		}
	}
	return Firmware{}, false
}

// Plan says which nodes a rolling push changes, in what order, and how carefully.
type Plan struct {
	// Targets are the nodes to change (addresses), changed one at a time in this order,
	// after Canary.
	Targets []string
	// Canary is changed first, then soaked; empty: the first target.
	Canary string
	// Peers are the other nodes clients use, which are never changed but count for the
	// "never take the last healthy node" rule.
	Peers []string
	// DNSPeers are resolvers clients use besides the nodes: each counts as one healthy
	// answering peer while it passes its DNS checks, asked each time the rule is.
	DNSPeers []DNSPeer
	// Uncounted are targets clients don't use (found but not adopted): they are changed,
	// but don't count as answering for the rule while another node is changed.
	Uncounted []string
	// Soak is how long a changed node runs, checked again after, before the next node starts.
	// A blocklist or overrides rollout soaks the last node too, and watches each node
	// through its soak (listsoak.go).
	Soak time.Duration
	// AllowSingle lets a change go ahead when the node is the only one: clients get no DNS
	// while it reboots or if the change breaks it.
	AllowSingle bool
	// Force starts a change that may reboot the node while another node is unhealthy (one
	// other node must still be answering: the last healthy node is never taken).
	Force bool
	// AllowDegraded are degraded reasons accepted after a change, besides those the node
	// already had before it.
	AllowDegraded []string
	Checks        Checks
	// RebootWait bounds the wait for a node to go down and come back; 0: 150 s.
	RebootWait time.Duration
	// ConfirmWait bounds the wait for a changed node to pass every check; 0: 180 s.
	ConfirmWait time.Duration
	// DryRun checks every node and the rule for each, and pushes nothing.
	DryRun bool
	// Stop, once closed, stops the rollout at the next safe point: before the next node is
	// started, or during a soak (the node soaking was already changed and checked). The node
	// being changed is finished and checked first. Cancelling the context instead stops at
	// once, wherever the node is: one pushed but not yet rebooted waits with a reboot pending
	// (make fleet-reboot-pending), one rebooting comes back or rolls itself back on its trial.
	Stop <-chan struct{}
}

// ErrStopped: the rollout was stopped (Plan.Stop) before it was done.
var ErrStopped = errors.New("stopped on request")

// stopped says whether the plan's Stop is closed.
func (p Plan) stopped() bool {
	select {
	case <-p.Stop:
		return true
	default:
		return false
	}
}

func (p Plan) rebootWait() time.Duration {
	if p.RebootWait > 0 {
		return p.RebootWait
	}
	return 150 * time.Second
}

func (p Plan) confirmWait() time.Duration {
	if p.ConfirmWait > 0 {
		return p.ConfirmWait
	}
	return 180 * time.Second
}

// Order is the targets as they are changed: the canary first, each node once.
func (p Plan) Order() []string {
	var out []string
	if p.Canary != "" {
		out = append(out, p.Canary)
	}
	for _, t := range p.Targets {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// all is every node the rule counts: the targets and the peers.
func (p Plan) all() []string {
	out := p.Order()
	for _, h := range p.Peers {
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// ErrSingle: the change would leave no node answering while it runs.
var ErrSingle = errors.New("this is the only node clients use: they get no DNS while it reboots or if the change breaks it")

// Result is what a rolling push did.
type Result struct {
	Done    []string // changed and checked (and not reverted)
	Skipped []string // already had the change (firmware already running)
	Failed  string   // the node the push stopped on
	Left    []string // not touched
	// Reverted are the nodes that took a blocklist or overrides the rollout then sent back
	// to the copy each had (the revert command), after a failure; NotReverted the ones it
	// couldn't, each with why and the way on.
	Reverted    []string
	NotReverted []NotReverted
}

// Prepare is what Rollout checks for one node, whose /status is st, before any node is
// touched: firmware for its chip image; the service the kind needs not off; its payload;
// and for a list, where the node would put it (ListPlacement; "" when the node decides).
// An error says why the node can't take the change, and the rollout doesn't start.
func (ch Change) Prepare(ctx context.Context, h string, st release.NodeStatus) (payload []byte, place string, err error) {
	if ch.Kind == release.Firmware {
		fw, ok := ch.firmwareFor(st)
		if !ok {
			return nil, "", fmt.Errorf("%s runs chip image %q (board %s): no firmware given for it", h, st.Image, st.Board)
		}
		return nil, "", FirmwareAddressCheck(h, st, fw.App)
	}
	// A node with the service off refuses its releases: say so before any node is
	// touched, rather than stop the rollout part way.
	if svc := serviceFor(ch.Kind); svc != "" && st.ServiceOff(svc) {
		return nil, "", fmt.Errorf("%s: %s is off in its node config, so it refuses %s releases: leave it out of "+
			"the rollout, or turn %s on in its config first", h, svc, ch.Kind, svc)
	}
	if ch.Payload == nil {
		return nil, "", errors.New("no payload for " + ch.Kind.String())
	}
	if payload, err = ch.Payload(ctx, h, st); err != nil {
		return nil, "", fmt.Errorf("%s: %w", h, err)
	}
	// A list that fits no tier of the node's blocking memory: refused here, as the node
	// would at the push.
	if ch.Kind == release.Blocklist || ch.Kind == release.Overrides {
		if place, err = ListPlacement(h, ch.Kind, payload, int64(len(payload)), st); err != nil {
			return nil, "", err
		}
	}
	return payload, place, nil
}

// FirmwareAddressCheck refuses firmware that would leave the node at h, whose /status is
// st, with no address, or another one, where its address depends on the one built into its
// firmware: a node whose address is that one (address_from "firmware") gets only an image
// with the same address built in; a node with no board partition (a transitional image's
// built-in board), whose config gives its address, only an image with an address built in,
// which it falls back on if its config is ever refused or gone (no DHCP: firmware/main/net.c).
// Such an image comes from a build without the deployment's firmware/local.mk
// (STATIC_IP_<board>; make fleet-firmware refuses that build), or is an exported chip image.
// An image from before the firmware marked its address (release.BuiltinAddress) is not
// checked.
func FirmwareAddressCheck(h string, st release.NodeStatus, app []byte) error {
	built, known := release.BuiltinAddress(app)
	if !known || st.Config == nil {
		return nil
	}
	has := "none"
	if built != "" {
		has = built
	}
	ip := st.Config.IP
	if p, err := netip.ParsePrefix(ip); err == nil {
		ip = p.Addr().String()
	}
	switch {
	case st.Config.AddressFrom == "firmware" && built != ip:
		return fmt.Errorf("%s: its address (%s) is the one built into the firmware it runs, and this image has %s built in: "+
			"it would come up without it. Build the image with the node's address (STATIC_IP_%s in firmware/local.mk, "+
			"make fleet-firmware)", h, ip, has, st.Board)
	case st.Config.AddressFrom == "config" && st.BoardSource != "partition" && built == "":
		return fmt.Errorf("%s has no board partition, so if its config is ever refused it falls back on the address built "+
			"into its firmware, and this image has none: it would be left with no address. Build the image with the "+
			"node's address (STATIC_IP_%s in firmware/local.mk, make fleet-firmware)", h, st.Board)
	case st.Config.AddressFrom == "config" && st.BoardSource != "partition" && built != ip && documentation(built):
		return fmt.Errorf("%s has no board partition, so if its config is ever refused it falls back on the address built "+
			"into its firmware, and this image has %s, a documentation address (CI's, or an example's): build the image "+
			"with the node's address (STATIC_IP_%s in firmware/local.mk, make fleet-firmware)", h, built, st.Board)
	}
	return nil
}

// documentation is whether a is in a documentation network (RFC 5737), as the examples
// and CI's transitional images use: never a node's.
func documentation(a string) bool {
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return false
	}
	for _, n := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		if netip.MustParsePrefix(n).Contains(ip) {
			return true
		}
	}
	return false
}

// FirmwareFor is the firmware the change has for the node whose /status is st, if any.
func (ch Change) FirmwareFor(st release.NodeStatus) (Firmware, bool) { return ch.firmwareFor(st) }

// Rollout changes the plan's nodes one at a time: the canary first, then each in order.
// For each: the rule (another node answers), the push, the reboot if the node needs one
// (the node waits for the controller where its firmware can, so two never reboot
// together), the checks (health, the build or seq applied, DNS), and the soak before the
// next. It stops at the first failure; a node that fails its own checks rolls itself back.
func (c *Client) Rollout(ctx context.Context, p Plan, ch Change) (Result, error) {
	var res Result
	order := p.Order()
	if len(order) == 0 {
		return res, errors.New("no nodes to change")
	}
	if c.Pusher == nil && !p.DryRun {
		return res, errors.New("no release key to sign with")
	}
	// Check every node and make every payload before touching the first.
	payloads := map[string][]byte{}
	places := map[string]string{} // where a list goes on each node, if known
	notes := map[string]string{}  // what else it does there (Change.Note)
	for _, h := range order {
		st, err := c.Status(ctx, h)
		if err != nil {
			res.Left = order
			return res, fmt.Errorf("%s: %w", h, err)
		}
		if payloads[h], places[h], err = ch.Prepare(ctx, h, st); err != nil {
			if ch.Payload != nil || ch.Kind == release.Firmware {
				res.Left = order
			}
			return res, err
		}
		notes[h] = ch.NoteFor(h, st)
	}
	for _, l := range p.Describe(ch.Kind) {
		c.logf("plan: %s", l)
	}
	outs := map[string]applyOut{} // what each node was pushed: what a revert may send back
	for i, h := range order {
		if p.stopped() {
			res.Left = order[i:]
			c.logf("stopped before %s, on request", h)
			return res, ErrStopped
		}
		c.progress(h, StepGate, "")
		if err := c.gate(ctx, p, h, ch.mayReboot()); err != nil {
			res.Failed, res.Left = h, order[i+1:]
			return res, fmt.Errorf("%s: not started: %w", h, err)
		}
		place := ""
		if places[h] != "" {
			place = " (" + places[h] + ")"
		}
		if p.DryRun {
			note := ""
			if notes[h] != "" {
				note = ": " + notes[h]
			}
			c.logf("%s: would push %s now%s%s", h, ch.Kind, place, note)
			c.progress(h, StepWouldPush, places[h])
			res.Left = append(res.Left, h)
			continue
		}
		if place != "" {
			c.logf("%s: pushing %s, expected%s", h, ch.Kind, place)
		}
		out, err := c.apply(ctx, p, ch, h, payloads[h])
		if out.pushed {
			outs[h] = out
		}
		if err != nil {
			took := out.pushed && c.tookIt(ctx, h, ch.Kind, out.before)
			return c.failed(ctx, p, ch, &res, order, i, took, outs, fmt.Errorf("%s: %w", h, err))
		}
		if out.skipped {
			res.Skipped = append(res.Skipped, h)
			c.progress(h, StepSkipped, "")
			continue
		}
		res.Done = append(res.Done, h)
		// A list soaks the last node too: its watch can still send every node back.
		if p.Soak > 0 && (i < len(order)-1 || ch.isList()) {
			c.logf("%s: soaking %v", h, p.Soak)
			c.progress(h, StepSoaking, p.Soak.String())
			err := c.soak(ctx, p, ch, h, out)
			switch {
			case errors.Is(err, ErrStopped):
				res.Left = order[i+1:]
				c.logf("%s: stopped during its soak, on request", h)
				return res, ErrStopped
			case err != nil && ctx.Err() != nil:
				res.Failed, res.Left = h, order[i+1:]
				return res, ctx.Err()
			case err != nil:
				return c.failed(ctx, p, ch, &res, order, i, true, outs, fmt.Errorf("%s: %w", h, err))
			}
			c.progress(h, StepChecked, "after the soak")
		}
		c.progress(h, StepDone, "")
	}
	return res, nil
}

// gate applies the rule before a node is changed: another node or a DNS peer passing its
// checks must be answering (or the plan allows a single node), and before a change that
// may reboot, every other node and DNS peer must be healthy unless the plan forces it.
func (c *Client) gate(ctx context.Context, p Plan, host string, mayReboot bool) error {
	var others []string
	for _, h := range p.all() {
		if h != host && !slices.Contains(p.Uncounted, h) {
			others = append(others, h)
		}
	}
	if len(others) == 0 && len(p.DNSPeers) == 0 {
		if !p.AllowSingle {
			return ruleError{ErrSingle}
		}
		c.logf("%s: the only node: clients get no DNS while it reboots", host)
		return nil
	}
	answering := 0
	var unwell []string
	for _, o := range others {
		h, err := c.Health(ctx, o)
		if err == nil && h.Answering && h.Code == 200 {
			err = c.Answers(ctx, o)
		} else if err == nil {
			err = errors.New(h.describe())
		}
		switch {
		case err != nil:
			unwell = append(unwell, fmt.Sprintf("%s (%v)", o, err))
		case h.State != "healthy":
			answering++
			unwell = append(unwell, fmt.Sprintf("%s (%s)", o, h.describe()))
		default:
			answering++
		}
	}
	for _, d := range p.DNSPeers {
		if err := c.checkDNSPeer(ctx, p, host, d); err != nil {
			unwell = append(unwell, fmt.Sprintf("DNS peer %s (%v)", d.Addr, err))
		} else {
			answering++
		}
	}
	if answering == 0 {
		return ruleError{fmt.Errorf("no other node or DNS peer is answering, so this would take the last healthy node: %s",
			strings.Join(unwell, "; "))}
	}
	if len(unwell) > 0 {
		if mayReboot && !p.Force {
			return ruleError{fmt.Errorf("another node is unhealthy and this change may reboot the node (force to go on with %d answering): %s",
				answering, strings.Join(unwell, "; "))}
		}
		c.logf("%s: going on with %d other node(s) answering; unhealthy: %s", host, answering, strings.Join(unwell, "; "))
	}
	return nil
}

// applyOut is what apply did on one node.
type applyOut struct {
	skipped bool     // it already had it
	allowed []string // the degraded reasons accepted after it: those it had before, and the plan's
	pushed  bool     // the release was sent (taken, or maybe taken if the push then failed)
	seq     uint64   // the seq it was pushed with
	before  release.NodeStatus
}

// apply pushes the change to one node, reboots it if needed, and checks it.
func (c *Client) apply(ctx context.Context, p Plan, ch Change, host string, payload []byte) (out applyOut, err error) {
	before, err := c.Status(ctx, host)
	if err != nil {
		return out, err
	}
	out.before = before
	hb, err := c.Health(ctx, host)
	if err != nil {
		return out, err
	}
	allowed := append(slices.Clone(hb.Reasons), p.AllowDegraded...)
	out.allowed = allowed
	var pushed release.Pushed
	var fw Firmware
	c.progress(host, StepPushing, "")
	if ch.Kind == release.Firmware {
		fw, _ = ch.firmwareFor(before)
		if before.ElfSHA256 == fw.Desc.ElfSHA256 && !ch.Reinstall {
			c.logf("%s: already runs %s %s (elf %s)", host, fw.Desc.Project, fw.Desc.Version, fw.Desc.ElfSHA256)
			out.skipped = true
			return out, nil
		}
		c.logf("%s: firmware %s %s (elf %s) over %s (elf %s)", host, fw.Desc.Project, fw.Desc.Version,
			fw.Desc.ElfSHA256, before.Version, before.ElfSHA256)
		out.pushed = true
		pushed, err = c.Pusher.PushFirmware(ctx, host, fw.App, release.FirmwareOptions{Image: fw.Image,
			Board: fw.Board, Later: before.Reboot != nil})
	} else {
		out.pushed = true
		pushed, err = c.Pusher.PushRelease(ctx, host, ch.Kind, payload)
	}
	if err != nil {
		return out, err
	}
	out.seq = pushed.Seq
	c.logf("%s: %s", host, pushed.Reply)
	rebooted, err := c.rebootIfNeeded(ctx, p, host, before, pushed.Node)
	if err != nil {
		return out, err
	}
	if ch.Kind == release.Firmware && !rebooted {
		return out, errors.New("the node took the firmware but neither rebooted nor says a reboot is pending")
	}
	applied := func(st release.NodeStatus, h Health) (string, error) {
		return appliedCheck(ch.Kind, pushed.Seq, before, fw, st, h)
	}
	c.progress(host, StepChecking, "")
	if err := c.verify(ctx, p, host, allowed, applied); err != nil {
		return out, err
	}
	c.progress(host, StepChecked, "")
	return out, nil
}

// rebootIfNeeded reboots the node if the release waits for it, or waits for the node to
// come back if it reboots by itself. It says whether the node rebooted.
func (c *Client) rebootIfNeeded(ctx context.Context, p Plan, host string, before release.NodeStatus, reply release.Reply) (bool, error) {
	pending, rebooting := reply.RebootPending, reply.Rebooting
	if !reply.JSON && !rebooting {
		st, err := c.Status(ctx, host)
		if err != nil {
			// Firmware from before JSON replies may have gone down to apply it.
			rebooting = true
		} else {
			pending = st.Reboot != nil && st.Reboot.Pending
		}
	}
	switch {
	case pending:
		// The push may have taken a while: the rule again, on the other nodes as they are
		// now, right before the node goes down.
		if err := c.gate(ctx, p, host, true); err != nil {
			return false, fmt.Errorf("it waits for a reboot, not rebooted: %w", err)
		}
		c.logf("%s: reboot pending; rebooting it now", host)
		c.progress(host, StepRebooting, "")
		if err := c.sendReboot(ctx, host, true); err != nil {
			return false, err
		}
	case rebooting:
		c.logf("%s: rebooting to apply it", host)
		c.progress(host, StepRebooting, "")
	default:
		return false, nil
	}
	return true, c.waitReboot(ctx, p, host, before)
}

// sendReboot sends the reboot command and checks the node says it reboots.
func (c *Client) sendReboot(ctx context.Context, host string, onlyIfPending bool) error {
	r, err := c.Pusher.PushRelease(ctx, host, release.Control, release.RebootPayload(0, onlyIfPending))
	if err != nil {
		return fmt.Errorf("reboot: %w", err)
	}
	c.logf("%s: %s", host, r.Reply)
	if r.Node.JSON && !r.Node.Rebooting {
		return fmt.Errorf("reboot: the node didn't reboot: %s", r.Node.Message)
	}
	return nil
}

// rebootSlack is how much longer than the wait so far a rebooted node's uptime may be:
// a node that rebooted just before the wait started.
const rebootSlack = 5 * time.Second

// waitReboot waits until the node has gone down and come back: it answers with a lower
// uptime than before, or, after not answering /status, with an uptime no longer than the
// wait (a /status that failed once, from a node that never rebooted, isn't a reboot).
func (c *Client) waitReboot(ctx context.Context, p Plan, host string, before release.NodeStatus) error {
	ctx, cancel := context.WithTimeout(ctx, p.rebootWait())
	defer cancel()
	t0 := time.Now()
	down := false
	for {
		tctx, tcancel := context.WithTimeout(ctx, 2*time.Second)
		st, err := c.Status(tctx, host)
		tcancel()
		switch {
		case err != nil:
			down = true
		case st.UptimeS < before.UptimeS ||
			down && time.Duration(st.UptimeS)*time.Second <= time.Since(t0)+rebootSlack:
			c.logf("%s: back after %.1fs (%s, elf %s, %s)", host, time.Since(t0).Seconds(), st.Version, st.ElfSHA256, st.OTAState)
			return nil
		}
		if sleep(ctx, c.poll()) != nil {
			if down {
				return fmt.Errorf("went down and didn't come back within %v", p.rebootWait())
			}
			return fmt.Errorf("didn't reboot within %v", p.rebootWait())
		}
	}
}

// errFatal marks a check that waiting won't fix.
type errFatal struct{ error }

// appliedCheck says whether the node runs what was pushed: "" when it does, else what it
// still waits for; an errFatal error when it won't (a firmware rollback, a refused config).
func appliedCheck(kind release.Kind, seq uint64, before release.NodeStatus, fw Firmware, st release.NodeStatus, h Health) (string, error) {
	stored := func(name string, s *Stored) (string, error) {
		switch {
		case s == nil:
			if st.Seq[kind.String()] >= seq {
				return "", nil // firmware that doesn't report it: the seq was recorded
			}
			return fmt.Sprintf("%s seq %d not recorded", name, seq), nil
		case s.Seq != seq:
			return fmt.Sprintf("%s seq %d, not %d (%s)", name, s.Seq, seq, s.State), nil
		case s.State == "failed":
			return "", errFatal{fmt.Errorf("%s seq %d failed to load", name, seq)}
		case s.State != "on":
			return fmt.Sprintf("%s %s", name, s.State), nil
		}
		return "", nil
	}
	switch kind {
	case release.Firmware:
		switch {
		case st.ElfSHA256 == before.ElfSHA256 && fw.Desc.ElfSHA256 != before.ElfSHA256: // not a reinstall
			return "", errFatal{fmt.Errorf("came back on the OLD build (elf %s): the update was rolled back", st.ElfSHA256)}
		case fw.Desc.ElfSHA256 == before.ElfSHA256 && before.Slot != "" && st.Slot == before.Slot:
			// A reinstall goes to the other slot: back on the old one, it was rolled back.
			return "", errFatal{fmt.Errorf("came back on the OLD slot (%s): the reinstall was rolled back", st.Slot)}
		case st.ElfSHA256 != fw.Desc.ElfSHA256:
			return "", errFatal{fmt.Errorf("runs elf %s, neither the old (%s) nor the new (%s) build",
				st.ElfSHA256, before.ElfSHA256, fw.Desc.ElfSHA256)}
		case st.OTAState != "valid":
			return "new build on " + st.OTAState + ", not yet confirmed", nil
		}
	case release.Config:
		switch {
		case st.Config == nil:
			return "", errFatal{errors.New("no config in /status")}
		case st.Config.Seq != seq:
			if st.Config.Error != "" {
				return "", errFatal{fmt.Errorf("runs config seq %d: %s", st.Config.Seq, st.Config.Error)}
			}
			return fmt.Sprintf("config seq %d, not %d", st.Config.Seq, seq), nil
		case st.Config.Trial:
			return "config on trial", nil
		}
	case release.Zones:
		if h.Zones == nil && st.Hosted != nil {
			return stored("zones", &Stored{State: st.Hosted.State, Seq: st.Hosted.Seq})
		}
		return stored("zones", h.Zones)
	case release.Blocklist, release.Overrides:
		s := h.Blocklist
		if kind == release.Overrides {
			s = h.Overrides
		}
		if wait, err := stored(kind.String(), s); wait != "" || err != nil {
			return wait, err
		}
		// On in /status too, where the node reports its lists.
		return listActive(kind, seq, st)
	}
	if st.Reboot != nil && st.Reboot.Pending {
		return "reboot still pending (" + strings.Join(st.Reboot.Reasons, ", ") + ")", nil
	}
	return "", nil
}

// verify waits until the node is in service (healthy, or degraded only for allowed
// reasons), runs what was pushed (applied, if given) and passes the DNS checks.
func (c *Client) verify(ctx context.Context, p Plan, host string, allowed []string,
	applied func(release.NodeStatus, Health) (string, error)) error {
	ctx, cancel := context.WithTimeout(ctx, p.confirmWait())
	defer cancel()
	var last string
	for {
		st, err := c.Status(ctx, host)
		var h Health
		if err == nil {
			h, err = c.Health(ctx, host)
		}
		if err == nil && applied != nil {
			var wait string
			wait, err = applied(st, h)
			if fe, ok := err.(errFatal); ok {
				return fe.error
			}
			if err == nil && wait != "" {
				err = errors.New(wait)
			}
		}
		if err == nil {
			err = h.InService(allowed)
		}
		// The checks wait for the services to start: a list or zones loaded after them
		// flush the cache their queries filled (a client's next query for a checked name
		// goes upstream again), and blocked names are checked only with the list on.
		if s := st.Starting(); err == nil && len(s) > 0 {
			err = fmt.Errorf("still starting: %s", strings.Join(s, ", "))
		}
		if err == nil {
			err = c.CheckDNS(ctx, host, st, h, p.Checks)
		}
		if err == nil {
			c.logf("%s: %s, answering, checks passed", host, h.State)
			return nil
		}
		if ctx.Err() == nil || last == "" { // not the wait running out mid-request
			last = err.Error()
		}
		if ctx.Err() != nil || sleep(ctx, c.poll()) != nil {
			return fmt.Errorf("not in service within %v: %s", p.confirmWait(), last)
		}
	}
}

// check is verify without waiting: one look at the node.
func (c *Client) check(ctx context.Context, p Plan, host string, allowed []string) error {
	h, err := c.Health(ctx, host)
	if err != nil {
		return err
	}
	if err := h.InService(allowed); err != nil {
		return err
	}
	st, err := c.Status(ctx, host)
	if err != nil {
		return err
	}
	return c.CheckDNS(ctx, host, st, h, p.Checks)
}

// RebootNow sends the node the reboot command once the rule allows it (as Reboot), and
// doesn't wait for it: for a node that comes back somewhere else (a new address on trial).
func (c *Client) RebootNow(ctx context.Context, p Plan, host string, onlyIfPending bool) error {
	if err := c.gate(ctx, p, host, true); err != nil {
		return fmt.Errorf("%s: not rebooted: %w", host, err)
	}
	if p.DryRun {
		c.logf("%s: would reboot now", host)
		return nil
	}
	if c.Pusher == nil {
		return errors.New("no release key to sign with")
	}
	if err := c.sendReboot(ctx, host, onlyIfPending); err != nil {
		return fmt.Errorf("%s: %w", host, err)
	}
	return nil
}

// RebootPending says whether the node waits for a reboot after a release, and why: from
// its /status (the reasons), or else its reply.
func (c *Client) RebootPending(ctx context.Context, host string, reply release.Reply) (bool, []string) {
	st, err := c.Status(ctx, host)
	if err == nil && st.Reboot != nil {
		return st.Reboot.Pending, st.Reboot.Reasons
	}
	return reply.RebootPending, nil
}

// Reboot reboots one node, coordinated as a rolling push is: only with another node
// answering (or the plan allowing a single node), then waits for it to come back in
// service. With onlyIfPending it does nothing unless a release waits for a reboot.
func (c *Client) Reboot(ctx context.Context, p Plan, host string, onlyIfPending bool) error {
	if c.Pusher == nil && !p.DryRun {
		return errors.New("no release key to sign with")
	}
	before, err := c.Status(ctx, host)
	if err != nil {
		return err
	}
	if before.Reboot == nil {
		return fmt.Errorf("%s runs firmware from before the reboot command (no \"reboot\" in /status)", host)
	}
	if onlyIfPending && !before.Reboot.Pending {
		c.logf("%s: no reboot pending", host)
		return nil
	}
	hb, err := c.Health(ctx, host)
	if err != nil {
		return err
	}
	if err := c.RebootNow(ctx, p, host, onlyIfPending); err != nil || p.DryRun {
		return err
	}
	if err := c.waitReboot(ctx, p, host, before); err != nil {
		return fmt.Errorf("%s: %w", host, err)
	}
	allowed := append(slices.Clone(hb.Reasons), p.AllowDegraded...)
	if err := c.verify(ctx, p, host, allowed, func(st release.NodeStatus, h Health) (string, error) {
		if st.Reboot != nil && st.Reboot.Pending {
			return "reboot still pending", nil
		}
		return "", nil
	}); err != nil {
		return fmt.Errorf("%s: %w", host, err)
	}
	return nil
}
