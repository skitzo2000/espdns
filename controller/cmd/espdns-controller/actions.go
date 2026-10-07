package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The node actions, each a job (under the fleet lock, in the action log, its progress
// live), signed with the release key (internal/keys) as the CLI signs them:
//
//	identify        {"node": "192.0.2.52", "seconds": 30}  the LED flickers (1 to 3600 s), as espdns identify
//	pause           {"node": "...", "seconds": 300}             blocking off for that long (at most a week; 0
//	                                                            resumes it), as espdns pause -for
//	flush           {"node": "..."}                             the cache is dropped, as espdns flush
//	revert          {"node": "...", "list": "blocklist"}        the blocklist (or "overrides", or the hosted
//	                                                            "zones") goes back to the older copy the node
//	                                                            keeps, as espdns revert
//	reboot-pending  {"node": "..."}                             a coordinated reboot of a node a release left
//	                                                            waiting for one, as make fleet-reboot-pending
//
// The node must be one the controller knows: the page can't make it sign a release for any
// address. Identify takes any node it knows (found over mDNS or in settings.json), to tell
// a new board from the others; flush, pause, revert and reboot-pending only a node in settings.json, as
// the fleet-* targets run with -mdns 0. A release is signed for the node ID the address
// reports, so a host that only advertises itself over mDNS could have one signed for
// another node's ID and replay it there: an identify (the LED flickers) is harmless, a
// flush, a revert or a reboot is not. Without a release key, or for a node it doesn't take, the job
// isn't queued (400, saying why). The key is read again when the job runs, so one
// replaced or opened up while it waited is not used.

const (
	identifyDefault = 30
	identifyMax     = int(release.IdentifyMax / time.Second)
	// A pause: espdns pause's default, and the longest the page and the CLI take.
	pauseDefault = 300
	pauseMax     = int(release.PauseMax / time.Second)
)

type actions struct {
	dataDir string
	key     keys.Source
	// known are the addresses of the nodes the controller knows.
	known func() []string
	// client is a fleet client for a job (its Logf and Pusher are set by the job).
	client func() *fleet.Client
	// http reaches the nodes for identify and flush; nil: the Pusher's default.
	http *http.Client
}

func (a actions) kinds() map[string]jobs.Kind {
	return map[string]jobs.Kind{"identify": a.identify, "flush": a.flush, "pause": a.pause, "revert": a.revert,
		"reboot-pending": a.rebootPending}
}

type nodeParams struct {
	Node    string  `json:"node"`
	Seconds *int    `json:"seconds,omitempty"`
	List    *string `json:"list,omitempty"`
}

// parse reads the params and checks the key is there: errors here refuse the job before it
// is queued. seconds: the kind takes "seconds" (identify, pause). listedOnly: the node must
// be in settings.json, not only found over mDNS.
func (a actions) parse(raw json.RawMessage, seconds, listedOnly bool) (nodeParams, error) {
	return a.parseList(raw, seconds, false, listedOnly)
}

// parseList is parse, for a kind that may take "list" too.
func (a actions) parseList(raw json.RawMessage, seconds, list, listedOnly bool) (nodeParams, error) {
	var p nodeParams
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("params: %v", err)
	}
	if p.Node == "" {
		return p, errors.New(`params: need "node", the node's address`)
	}
	if p.Seconds != nil && !seconds {
		return p, errors.New(`params: "seconds" is only for identify and pause`)
	}
	if p.List != nil && !list {
		return p, errors.New(`params: "list" is only for revert`)
	}
	if listedOnly {
		s, err := settings.Load(settings.Path(a.dataDir))
		if err != nil {
			return p, err
		}
		if !slices.Contains(s.Nodes, p.Node) {
			return p, fmt.Errorf("%s is not in settings.json: this action is only for the nodes listed there, not ones only found over mDNS", p.Node)
		}
	} else if !slices.Contains(a.known(), p.Node) {
		return p, fmt.Errorf("%s is not a node the controller knows (found over mDNS or in settings.json)", p.Node)
	}
	_, err := a.signer()
	return p, err
}

// signer is the release key, read now.
func (a actions) signer() (*ecdsa.PrivateKey, error) {
	k, err := a.key.Key()
	if errors.Is(err, keys.ErrNoKey) {
		return nil, fmt.Errorf("no release key, so no actions: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("the release key can't be used, so no actions: %v", err)
	}
	return k, nil
}

func (a actions) identify(raw json.RawMessage) (jobs.Func, error) {
	p, err := a.parse(raw, true, false)
	if err != nil {
		return nil, err
	}
	secs := identifyDefault
	if p.Seconds != nil {
		secs = *p.Seconds
	}
	if secs < 1 || secs > identifyMax {
		return nil, fmt.Errorf("seconds: 1 to %d, not %d", identifyMax, secs)
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		return a.control(ctx, run, p.Node, fmt.Sprintf("identify for %d s (the LED flickers)", secs),
			release.IdentifyPayload(time.Duration(secs)*time.Second), true)
	}, nil
}

func (a actions) flush(raw json.RawMessage) (jobs.Func, error) {
	p, err := a.parse(raw, false, true)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		return a.control(ctx, run, p.Node, "flush the cache", release.FlushPayload(), false)
	}, nil
}

// pause turns blocking off on the node for a while (or, with 0 seconds, back on), as
// espdns pause -for: live, and not kept across a reboot.
func (a actions) pause(raw json.RawMessage) (jobs.Func, error) {
	p, err := a.parse(raw, true, true)
	if err != nil {
		return nil, err
	}
	secs := pauseDefault
	if p.Seconds != nil {
		secs = *p.Seconds
	}
	if secs < 0 || secs > pauseMax {
		return nil, fmt.Errorf("seconds: 0 (resume) to %d (a week), not %d", pauseMax, secs)
	}
	what := "resume blocking"
	if secs > 0 {
		what = fmt.Sprintf("pause blocking for %s", time.Duration(secs)*time.Second)
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		return a.control(ctx, run, p.Node, what, release.PausePayload(time.Duration(secs)*time.Second), false)
	}, nil
}

// revert sends the node's blocklist, overrides or hosted zones back to the older copy it
// keeps in its other slot. The node refuses it when it holds no older copy (the reply says
// why); a list that only fits once the one in use is gone reverts at its next reboot (reboot
// pending, which reboot-pending then does, coordinated). Zones always revert live.
func (a actions) revert(raw json.RawMessage) (jobs.Func, error) {
	p, err := a.parseList(raw, false, true, true)
	if err != nil {
		return nil, err
	}
	list := "blocklist"
	if p.List != nil {
		list = *p.List
	}
	k, err := release.ParseKind(list)
	if err != nil {
		return nil, fmt.Errorf(`list: "blocklist", "overrides" or "zones", not %q`, list)
	}
	payload, err := release.RevertPayload(k)
	if err != nil {
		return nil, fmt.Errorf(`list: "blocklist", "overrides" or "zones", not %q`, list)
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		return a.control(ctx, run, p.Node, fmt.Sprintf("revert the %s to the older copy it keeps", list), payload, false)
	}, nil
}

type controlResult struct {
	Node  string `json:"node"`
	Seq   uint64 `json:"seq"`
	Reply string `json:"reply"`
}

// control signs a control release for the node and sends it, as the CLI's control commands.
// unadopted (identify alone) also signs for a node not adopted yet (release.Pusher.Unadopted).
func (a actions) control(ctx context.Context, run *jobs.Run, host string, what string, payload []byte,
	unadopted bool) (any, error) {
	k, err := a.signer()
	if err != nil {
		return nil, err
	}
	run.Logf("%s: %s: signing a control release with the release key %s", host, what, keys.Fingerprint(k))
	p := &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(a.dataDir), Unadopted: unadopted, Client: a.http}
	r, err := p.PushRelease(ctx, host, release.Control, payload)
	if err != nil {
		return nil, err
	}
	run.Logf("%s: %s", host, r.Reply)
	return controlResult{Node: host, Seq: r.Seq, Reply: r.Node.Message}, nil
}

func (a actions) rebootPending(raw json.RawMessage) (jobs.Func, error) {
	p, err := a.parse(raw, false, true)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, run *jobs.Run) (any, error) {
		host := p.Node
		k, err := a.signer()
		if err != nil {
			return nil, err
		}
		c := a.client()
		c.Logf = run.Logf
		c.Pusher = &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(a.dataDir), Client: c.HTTP}
		st, err := c.Status(ctx, host)
		if err != nil {
			return nil, err
		}
		switch {
		case st.Reboot == nil:
			return nil, fmt.Errorf("%s runs firmware from before the reboot command (no \"reboot\" in /status)", host)
		case !st.Reboot.Pending:
			return nil, fmt.Errorf("%s: no reboot pending, so not rebooted (this only reboots a node a release left waiting for one)", host)
		}
		run.Logf("%s: reboot pending (%s): rebooting it, coordinated: only while another node or a DNS peer answers",
			host, strings.Join(st.Reboot.Reasons, ", "))
		s, err := settings.Load(settings.Path(a.dataDir))
		if err != nil {
			return nil, err
		}
		// As make fleet-reboot-pending: the settings' nodes (no mDNS) and DNS peers count.
		if !slices.Contains(s.Nodes, host) {
			return nil, fmt.Errorf("%s is no longer in settings.json: not rebooted", host)
		}
		ns, err := c.Discover(ctx, 0, s.Nodes)
		if err != nil {
			return nil, err
		}
		plan := fleet.Plan{Targets: []string{host}, Checks: fleet.Checks{Forwarded: []string{"example.com"}}, Stop: run.Stop()}
		for _, d := range s.DNSPeers {
			plan.DNSPeers = append(plan.DNSPeers, fleet.DNSPeer{Addr: d, Zones: s.DNSPeerZones})
		}
		if len(s.DNSPeers) > 0 {
			run.Logf("DNS peers: %s", strings.Join(s.DNSPeers, ", "))
		}
		c.Count(ctx, &plan, ns, nil)
		if err := c.Reboot(ctx, plan, host, true); err != nil {
			if errors.Is(err, fleet.ErrSingle) {
				err = fmt.Errorf("%w (add the other nodes or a DNS peer to settings.json; the CLI's -allow-single is not offered here)", err)
			}
			return nil, err
		}
		run.Logf("%s: rebooted, back in service, no reboot pending", host)
		return map[string]any{"node": host, "rebooted": true}, nil
	}, nil
}
