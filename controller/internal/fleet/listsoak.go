package fleet

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

// A blocklist or overrides rollout (docs/design.md, Blocking: checks before a push) goes
// as any other, canary first and one node at a time under the rule, and besides:
//
//   - each node is soaked, the last one too, and watched through its soak: in service, the
//     list it took still on in /status at the seq pushed, no reboot, and its servfail and
//     dropped query counts not jumping (where /status reports them); after the soak, its
//     DNS checks again (CHECK_BLOCKED blocked, MUST_RESOLVE resolving, against that node);
//   - on a failure on a node that took the list (its checks, its soak, a reboot to load it
//     that doesn't come back), every node that took it is sent back to the copy it had
//     (the revert command, release.RevertPayload), the failed node first, then the others
//     newest first, so the fleet runs one list again; the nodes not yet changed are left
//     untouched. A revert applies live, or at a reboot the node asks for (two copies don't
//     fit), done as any release's, under the rule: never the last healthy node. A node the
//     revert can't send back (none older there, a reboot the rule holds back, a node that
//     doesn't answer) is named with why and the way on (Result.NotReverted).
//
// A failure of the rule itself (another node unhealthy, none answering) is not the list's:
// nothing is reverted, as a stop on request isn't.

// ruleError: the rule (never the last healthy node) held a node back. Not the change's
// fault: a list rollout that stops on it reverts nothing.
type ruleError struct{ error }

func (e ruleError) Unwrap() error { return e.error }

// isRule says whether err is the rule holding a node back.
func isRule(err error) bool {
	var re ruleError
	return errors.As(err, &re)
}

// NotReverted is a node that took a list a failed rollout couldn't send back.
type NotReverted struct {
	Host  string `json:"host"`
	Why   string `json:"why"`
	WayOn string `json:"way_on"`
}

// soakMinQueries is how many queries a soak must see before its counters are judged.
const soakMinQueries = 50

// watchEvery is how often a list's soak looks at the node: a sixth of the soak, between
// floor and 10 s, and never longer than the soak.
func (p Plan) watchEvery(floor time.Duration) time.Duration {
	d := min(max(p.Soak/6, floor), max(10*time.Second, floor))
	if p.Soak > 0 {
		d = min(d, p.Soak)
	}
	return d
}

// Describe says, in lines, how the plan goes for a change of kind: the canary, the order,
// the checks and soak after each node, what a failure does. Rollout logs it (a dry run
// too); the Push page shows it.
func (p Plan) Describe(kind release.Kind) []string {
	order := p.Order()
	if len(order) == 0 {
		return nil
	}
	var out []string
	if p.Canary != "" {
		out = append(out, fmt.Sprintf("canary %s first", order[0]))
	} else {
		out = append(out, fmt.Sprintf("%s first (no canary chosen: the first node)", order[0]))
	}
	if len(order) > 1 {
		out = append(out, "then one at a time, the same way: "+strings.Join(order[1:], ", "))
	}
	if kind == release.Blocklist || kind == release.Overrides {
		after := fmt.Sprintf("after each push: in service, the %s's seq on in its /status, its DNS checks", kind)
		if p.Soak > 0 {
			after += fmt.Sprintf("; then a soak of %v, the last node too, watched every %v (in service, the %s still on, "+
				"no reboot, servfail and dropped queries not jumping) and its DNS checks again, before the next starts",
				p.Soak, p.watchEvery(time.Second), kind)
		}
		out = append(out, after,
			fmt.Sprintf("on a failure: every node that took this %s goes back to the copy it had (the revert: live, or at "+
				"a reboot coordinated as a release's, never the last healthy node), the rollout stops, and the nodes not "+
				"yet changed are left untouched", kind))
		return out
	}
	if p.Soak > 0 && len(order) > 1 {
		out = append(out, fmt.Sprintf("after each push: its checks; each node but the last then soaks %v and is checked "+
			"again before the next starts", p.Soak))
	} else {
		out = append(out, "after each push: its checks")
	}
	return append(out, "on a failure: the rollout stops there, and the nodes after it are left untouched")
}

// soakWatch is what a list's soak compares the node with.
type soakWatch struct {
	uptime int64
	prior  *release.QueryCounts // since its boot, before the push
	base   *release.QueryCounts // at the soak's start
	misses int                  // looks in a row the node didn't answer
}

// soakMisses is how many looks in a row a soaking node may not answer (/status or /health
// failing to read: a lost packet, a busy node) before that is its failure: one missed look
// doesn't send every node that took the list back.
const soakMisses = 3

// errMissed: a look at a soaking node that couldn't read it, fewer than soakMisses in a row.
var errMissed = errors.New("no answer")

// readError is a look at a node that couldn't read its /status or /health.
type readError struct{ error }

func (e readError) Unwrap() error { return e.error }

// soak runs the node for the plan's soak and checks it again after; a list's soak watches
// it all along (watch). ErrStopped on a stop, the context's error if it ends.
func (c *Client) soak(ctx context.Context, p Plan, ch Change, h string, out applyOut) error {
	t := time.NewTimer(p.Soak)
	defer t.Stop()
	var w *soakWatch
	var tick <-chan time.Time
	if ch.isList() {
		var st release.NodeStatus
		var err error
		for range soakMisses {
			if st, err = c.Status(ctx, h); err == nil || ctx.Err() != nil {
				break
			}
			if sleep(ctx, c.poll()) != nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("at its soak's start: %w", err)
		}
		w = &soakWatch{uptime: st.UptimeS, prior: out.before.Queries, base: st.Queries}
		tk := time.NewTicker(p.watchEvery(c.poll()))
		defer tk.Stop()
		tick = tk.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.Stop:
			return ErrStopped
		case <-tick:
			if err := c.look(ctx, ch.Kind, h, out, w); err != nil && !errors.Is(err, errMissed) {
				return fmt.Errorf("during its soak: %w", err)
			}
		case <-t.C:
			c.progress(h, StepChecking, "after the soak")
			if w != nil {
				for {
					err := c.look(ctx, ch.Kind, h, out, w)
					if err == nil {
						break
					}
					if !errors.Is(err, errMissed) {
						return fmt.Errorf("after the soak: %w", err)
					}
					if err := sleep(ctx, c.poll()); err != nil {
						return err
					}
				}
			}
			if err := c.check(ctx, p, h, out.allowed); err != nil {
				return fmt.Errorf("after the soak: %w", err)
			}
			return nil
		}
	}
}

// look is watch, counting the looks in a row that couldn't read the node: errMissed while
// they are fewer than soakMisses, then the read's error.
func (c *Client) look(ctx context.Context, kind release.Kind, h string, out applyOut, w *soakWatch) error {
	err := c.watch(ctx, kind, h, out, w)
	var re readError
	if !errors.As(err, &re) || ctx.Err() != nil {
		w.misses = 0
		return err
	}
	if w.misses++; w.misses >= soakMisses {
		return fmt.Errorf("it didn't answer %d looks in a row: %w", w.misses, re.error)
	}
	c.logf("%s: no answer while it soaks (%v): looking again", h, re.error)
	return errMissed
}

// watch is one look at a node soaking a list: in service, the list still on at the seq
// pushed, not rebooted, its counters not jumping. A readError when it can't be read.
func (c *Client) watch(ctx context.Context, kind release.Kind, h string, out applyOut, w *soakWatch) error {
	hh, err := c.Health(ctx, h)
	if err != nil {
		return readError{err}
	}
	if err := hh.InService(out.allowed); err != nil {
		return err
	}
	st, err := c.Status(ctx, h)
	if err != nil {
		return readError{err}
	}
	if st.UptimeS < w.uptime {
		return fmt.Errorf("it rebooted (up %d s)", st.UptimeS)
	}
	w.uptime = st.UptimeS
	wait, err := listActive(kind, out.seq, st)
	if err == nil && wait == "" && st.List(kind) == nil {
		// Firmware that doesn't report its lists: its /health's.
		s := hh.Blocklist
		if kind == release.Overrides {
			s = hh.Overrides
		}
		if s != nil && (s.Seq != out.seq || s.State != "on") {
			wait = fmt.Sprintf("%s seq %d %s, not seq %d on", kind, s.Seq, s.State, out.seq)
		}
	}
	if err != nil {
		return err
	}
	if wait != "" {
		return fmt.Errorf("its %s is no longer the one pushed: %s", kind, wait)
	}
	return countsJump(w.prior, w.base, st.Queries)
}

// countsJump says whether the node's servfail or dropped share of the queries since base
// jumped: with at least soakMinQueries since, a share over twice the node's share before
// the push (prior, since its boot) and over 10 points above it. nil when it doesn't
// report them.
func countsJump(prior, base, now *release.QueryCounts) error {
	if base == nil || now == nil || now.Total < base.Total || now.Total-base.Total < soakMinQueries {
		return nil
	}
	total := float64(now.Total - base.Total)
	for _, f := range []struct {
		name     string
		get      func(*release.QueryCounts) uint64
		hadShare float64
	}{
		{"servfail", func(q *release.QueryCounts) uint64 { return q.Servfail }, 0},
		{"dropped", func(q *release.QueryCounts) uint64 { return q.Dropped }, 0},
	} {
		if prior != nil && prior.Total > 0 {
			f.hadShare = float64(f.get(prior)) / float64(prior.Total)
		}
		if f.get(now) < f.get(base) {
			continue
		}
		share := float64(f.get(now)-f.get(base)) / total
		if share > 2*f.hadShare && share > f.hadShare+0.10 {
			return fmt.Errorf("%s jumped: %d of %d queries in its soak (%.0f%%), %.0f%% before the push",
				f.name, f.get(now)-f.get(base), now.Total-base.Total, 100*share, 100*f.hadShare)
		}
	}
	return nil
}

// listActive says whether the node's /status reports its list of kind on at seq: "" when
// it does or doesn't report its lists, else what it still waits for; an errFatal error
// when the list failed to load.
func listActive(kind release.Kind, seq uint64, st release.NodeStatus) (string, error) {
	l := st.List(kind)
	switch {
	case l == nil:
		return "", nil
	case l.Seq == seq && l.State == "failed":
		return "", errFatal{fmt.Errorf("%s seq %d failed to load: %s", kind, seq, l.Error)}
	case l.Seq != seq || l.State != "on":
		return fmt.Sprintf("/status %s seq %d %s, not seq %d on", kind, l.Seq, l.State, seq), nil
	}
	return "", nil
}

// tookIt says whether a node whose push failed took the list anyway: its seq for the kind
// moved on from before. A node that can't be read may have: true, and the revert says what
// it finds.
func (c *Client) tookIt(ctx context.Context, h string, kind release.Kind, before release.NodeStatus) bool {
	if kind != release.Blocklist && kind != release.Overrides {
		return false
	}
	st, err := c.Status(ctx, h)
	if err != nil {
		return true
	}
	return st.Seq[kind.String()] > before.Seq[kind.String()]
}

// failed ends a rollout that failed at order[i]. For a list (unless the rule held the node
// back, or the context ended), every node that took it is reverted: the failed node first
// if took, then the ones done, newest first. outs are what each node was pushed: a revert
// sends back only this rollout's list (revertList).
func (c *Client) failed(ctx context.Context, p Plan, ch Change, res *Result, order []string, i int, took bool,
	outs map[string]applyOut, err error) (Result, error) {
	h := order[i]
	res.Failed, res.Left = h, order[i+1:]
	if !ch.isList() || isRule(err) || ctx.Err() != nil {
		return *res, err
	}
	if !took && !slices.Contains(res.Done, h) {
		// It never took it (refused it, or wasn't reached before the push): the list didn't
		// fail anywhere, and the nodes done keep it, as after a stop.
		c.logf("%s didn't take the %s: nothing reverted", h, ch.Kind)
		return *res, err
	}
	back := []string{h}
	for j := len(res.Done) - 1; j >= 0; j-- {
		if res.Done[j] != h {
			back = append(back, res.Done[j])
		}
	}
	c.logf("%v: sending the %s back on every node that took it: %s", err, ch.Kind, strings.Join(back, ", "))
	notReverted := func(n string, rerr error) {
		nr := NotReverted{Host: n, Why: rerr.Error(), WayOn: wayOn(ch.Kind, n, rerr)}
		res.NotReverted = append(res.NotReverted, nr)
		c.logf("%s: not reverted: %s; the way on: %s", n, nr.Why, nr.WayOn)
		c.progress(n, StepNotReverted, nr.Why+"; the way on: "+nr.WayOn)
	}
	for k, n := range back {
		if ctx.Err() != nil {
			// The rollout was ended (the controller shutting down): the rest are named, each
			// as it may be, not left out.
			for _, m := range back[k:] {
				notReverted(m, revertError{fmt.Errorf("the rollout ended (%v) before its revert", ctx.Err()), "ended",
					outs[m].seq})
			}
			break
		}
		detail, rerr := c.revertList(ctx, p, ch.Kind, n, outs[n])
		switch {
		case errors.Is(rerr, errNotTaken):
			c.logf("%s: %v: nothing to send back", n, rerr)
			continue
		case rerr != nil && ctx.Err() != nil:
			notReverted(n, revertError{fmt.Errorf("the rollout ended (%v) during its revert: %w", ctx.Err(), rerr), "ended",
				outs[n].seq})
			continue
		case rerr != nil:
			notReverted(n, rerr)
			continue
		}
		res.Reverted = append(res.Reverted, n)
		res.Done = slices.DeleteFunc(res.Done, func(d string) bool { return d == n })
		c.logf("%s: reverted: %s", n, detail)
		c.progress(n, StepReverted, detail)
	}
	return *res, err
}

// errNotTaken: the node a revert was for never took this rollout's list (its seq for the
// kind is the one it had before): nothing to send back.
var errNotTaken = errors.New("it never took this rollout's list")

// revertError is a revert that didn't happen, by what held it back.
type revertError struct {
	error
	how string // "refused", "reboot", "unreachable", "changed" (a newer list since), "ended"
	seq uint64 // this rollout's seq on the node, if known
}

func (e revertError) Unwrap() error { return e.error }

// wayOn says what to do about a node a revert couldn't send back.
func wayOn(kind release.Kind, h string, err error) string {
	var re revertError
	errors.As(err, &re)
	list := ""
	if kind == release.Overrides {
		list = " -kind overrides"
	}
	which := ""
	if re.seq != 0 {
		which = fmt.Sprintf(" seq %d", re.seq)
	}
	switch re.how {
	case "changed":
		return fmt.Sprintf("find out which %s it should run (espdns status, or the Nodes page); a revert there now would undo the newer "+
			"one, so only if that is the one to undo: espdns revert -host %s%s", kind, h, list)
	case "ended":
		return fmt.Sprintf("check it (espdns status, or the Nodes page): if it still runs this rollout's %s%s, espdns revert -host %s%s",
			kind, which, h, list)
	case "reboot":
		return fmt.Sprintf("it goes back at its next reboot: once another node or a DNS peer answers and the others are "+
			"healthy, espdns reboot -host %s -if-pending (or its reboot on the Nodes page)", h)
	case "unreachable":
		return fmt.Sprintf("find out why it doesn't answer (espdns status, its /status); once it does, if it "+
			"runs this rollout's %s%s, espdns revert -host %s%s", kind, which, h, list)
	}
	if kind == release.Overrides {
		return fmt.Sprintf("push the overrides it should run (the older file, or one with no entries) to %s with a new "+
			"rollout, after a dry run (pausing blocking leaves overrides on)", h)
	}
	return fmt.Sprintf("pause blocking on it (espdns pause -host %s -for 1h: it ends by itself, and at a reboot), "+
		"then push the list it should run to it with a new rollout, after a dry run", h)
}

// revertList sends the node's list of kind back to the older copy it keeps (the revert
// command), reboots it if the node asks for that (two copies don't fit), under the rule,
// and waits for it to be in service on the older copy. It says which copy. out is what
// this rollout pushed it: only that list is sent back. A node that never took it is
// errNotTaken; one that took a newer list since (another push) isn't reverted, as that
// would undo the newer one.
func (c *Client) revertList(ctx context.Context, p Plan, kind release.Kind, h string, out applyOut) (string, error) {
	c.progress(h, StepReverting, "")
	before, err := c.Status(ctx, h)
	if err != nil {
		return "", revertError{fmt.Errorf("can't be read, so it may hold the new %s: %w", kind, err), "unreachable", out.seq}
	}
	from, prior := before.Seq[kind.String()], out.before.Seq[kind.String()]
	switch {
	case from <= prior:
		return "", fmt.Errorf("%w (%s seq %d, as before it)", errNotTaken, kind, from)
	case out.seq != 0 && from != out.seq:
		return "", revertError{fmt.Errorf("it took %s seq %d since this rollout's seq %d (another push): not sent back, "+
			"which would undo that one", kind, from, out.seq), "changed", out.seq}
	}
	l := before.List(kind)
	if l != nil && l.RevertedFrom == from && l.Seq != from {
		// Already sent back (a revert from elsewhere): on the copy it had.
		return fmt.Sprintf("already back on seq %d (from seq %d)", l.Seq, from), nil
	}
	if l != nil && l.Slot == nil {
		return "", revertError{errors.New("its firmware is from before the revert command"), "refused", out.seq}
	}
	allowed := slices.Clone(p.AllowDegraded)
	if hb, err := c.Health(ctx, h); err == nil {
		allowed = append(allowed, hb.Reasons...)
	}
	payload, err := release.RevertPayload(kind)
	if err != nil {
		return "", err
	}
	r, err := c.Pusher.PushRelease(ctx, h, release.Control, payload)
	if err != nil {
		if e := err.Error(); !strings.Contains(e, " rejected: ") && !strings.Contains(e, "update its firmware") { // not reached
			return "", revertError{fmt.Errorf("the revert didn't reach it: %w", err), "unreachable", out.seq}
		}
		return "", revertError{fmt.Errorf("the revert was refused: %w", err), "refused", out.seq}
	}
	c.logf("%s: %s", h, r.Reply)
	if _, err := c.rebootIfNeeded(ctx, p, h, before, r.Node); err != nil {
		how := "reboot"
		if !isRule(err) {
			how = "unreachable"
		}
		return "", revertError{fmt.Errorf("revert: %w", err), how, out.seq}
	}
	// In service on the older copy: it answers (the list's own checks were what failed).
	q := p
	q.Checks = Checks{Off: true}
	var to string
	err = c.verify(ctx, q, h, allowed, func(st release.NodeStatus, hh Health) (string, error) {
		l := st.List(kind)
		if l == nil { // firmware that doesn't report its lists: its /health's
			s := hh.Blocklist
			if kind == release.Overrides {
				s = hh.Overrides
			}
			if s == nil || s.Seq == from {
				return fmt.Sprintf("%s still seq %d", kind, from), nil
			}
			to = fmt.Sprintf("back to seq %d (from seq %d)", s.Seq, from)
			return "", nil
		}
		switch {
		case l.Seq == from:
			return fmt.Sprintf("%s still seq %d", kind, from), nil
		case l.State == "failed":
			return "", errFatal{fmt.Errorf("the older %s (seq %d) failed to load: %s", kind, l.Seq, l.Error)}
		case l.State != "on":
			return fmt.Sprintf("%s seq %d %s", kind, l.Seq, l.State), nil
		}
		to = fmt.Sprintf("back to seq %d (from seq %d)", l.Seq, from)
		if l.Slot != nil && *l.Slot >= 0 {
			to += fmt.Sprintf(", slot %d", *l.Slot)
		}
		return "", nil
	})
	if err != nil {
		return "", revertError{fmt.Errorf("after the revert: %w", err), "unreachable", out.seq}
	}
	return to, nil
}
