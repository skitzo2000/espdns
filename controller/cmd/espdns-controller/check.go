package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// The "check" job looks at the whole fleet and changes nothing: every node in the
// settings or found over mDNS, read (/status, /health) and asked the DNS checks a rollout
// asks a node after its change (fleet.CheckDNS: each zone's SOA, a forwarded name), then
// each DNS peer asked its checks as the rule before a change asks them. It passes when
// every node is in service (healthy, answering, no reboot pending, its checks passed) and
// every DNS peer answers: what docs/rollout.md wants before a rollout starts.

// nodeCheck is one node's result.
type nodeCheck struct {
	Addr     string   `json:"addr"`
	Source   string   `json:"source"` // "settings", "mdns" or both
	State    string   `json:"state,omitempty"`
	Reasons  []string `json:"reasons,omitempty"`
	Firmware string   `json:"firmware,omitempty"`
	Config   string   `json:"config,omitempty"`
	Problems []string `json:"problems,omitempty"`
}

type peerCheck struct {
	Addr    string   `json:"addr"`
	Zones   []string `json:"zones,omitempty"`
	Problem string   `json:"problem,omitempty"`
}

type checkResult struct {
	Nodes    []nodeCheck `json:"nodes"`
	DNSPeers []peerCheck `json:"dns_peers"`
	OK       bool        `json:"ok"`
}

// checker makes check jobs. client is the fleet client for a job (its Logf set by the job);
// mdns is how long to browse for nodes besides the settings' (0: don't).
type checker struct {
	dataDir string
	mdns    time.Duration
	client  func() *fleet.Client
}

func (k checker) kind(params json.RawMessage) (jobs.Func, error) {
	if len(params) > 0 && string(params) != "null" && string(params) != "{}" {
		return nil, errors.New("check takes no params")
	}
	return k.run, nil
}

func (k checker) run(ctx context.Context, run *jobs.Run) (any, error) {
	s, err := settings.Load(settings.Path(k.dataDir))
	if err != nil {
		return nil, err
	}
	c := k.client()
	c.Logf = run.Logf
	run.Logf("checking the fleet: nodes %s from %s, DNS peers %s; mDNS %v", list(s.Nodes),
		settings.Path(k.dataDir), list(s.DNSPeers), k.mdns)
	ns, err := c.Discover(ctx, k.mdns, s.Nodes)
	if err != nil && k.mdns > 0 {
		run.Logf("%v: going on with the listed nodes only", err)
		ns, err = c.Discover(ctx, 0, s.Nodes)
	}
	if err != nil {
		return nil, err
	}
	res := checkResult{Nodes: []nodeCheck{}, DNSPeers: []peerCheck{}, OK: true}
	var zones, problems []string
	for _, n := range ns {
		select {
		case <-run.Stop():
			run.Logf("stopped before %s, on request", n.Addr)
			return res, fleet.ErrStopped
		case <-ctx.Done(): // the controller is shutting down: no node is "not in service" for that
			return res, ctx.Err()
		default:
		}
		r := k.node(ctx, c, n)
		if n.Status != nil {
			for _, z := range n.Status.Zones {
				if !z.Expired && !slices.Contains(zones, z.Name) {
					zones = append(zones, z.Name)
				}
			}
		}
		if len(r.Problems) > 0 {
			problems = append(problems, n.Addr+": "+strings.Join(r.Problems, "; "))
			run.Logf("%s: NOT in service: %s", n.Addr, strings.Join(r.Problems, "; "))
		} else {
			run.Logf("%s: %s, answering, DNS checks passed", n.Addr, r.State)
		}
		res.Nodes = append(res.Nodes, r)
	}
	if len(ns) == 0 {
		problems = append(problems, "no nodes: none in "+settings.Path(k.dataDir)+" and none found over mDNS")
	}
	for _, a := range s.DNSPeers {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		p := peerCheck{Addr: a, Zones: s.DNSPeerZones}
		if len(p.Zones) == 0 {
			p.Zones = zones
		}
		if err := c.CheckDNSPeer(ctx, fleet.DNSPeer{Addr: a, Zones: s.DNSPeerZones}, zones, nil); err != nil {
			p.Problem = err.Error()
			problems = append(problems, "DNS peer "+a+": "+p.Problem)
			run.Logf("DNS peer %s: NOT answering: %s", a, p.Problem)
		} else {
			run.Logf("DNS peer %s: answers %s and a forwarded name", a, list(p.Zones))
		}
		res.DNSPeers = append(res.DNSPeers, p)
	}
	if len(problems) > 0 {
		res.OK = false
		return res, fmt.Errorf("%d problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	run.Logf("all %d node(s) and %d DNS peer(s) in service", len(res.Nodes), len(res.DNSPeers))
	return res, nil
}

// node reads one node as the rollout's checks would after a change: in service, no reboot
// pending, its DNS checks passed.
func (k checker) node(ctx context.Context, c *fleet.Client, n fleet.Node) nodeCheck {
	r := nodeCheck{Addr: n.Addr, Source: n.Source}
	if n.Status == nil || n.Health == nil {
		r.Problems = append(r.Problems, "unreachable: "+n.Error)
		return r
	}
	st, h := n.Status, n.Health
	r.State, r.Reasons = h.State, h.Reasons
	r.Firmware = fmt.Sprintf("%s %s elf %s (%s, %s)", st.Project, st.Version, st.ElfSHA256, st.Slot, st.OTAState)
	if st.Config != nil {
		r.Config = fmt.Sprintf("%s seq %d, %s address", st.Config.Source, st.Config.Seq, st.Config.Address)
		if st.Config.AddressFrom != "" {
			r.Config += " (" + st.Config.AddressFrom + ")"
		}
	}
	c.Logf("%s: %s, board %s, chip image %s, firmware %s, config %s, up %s", n.Addr, st.NodeID, st.Board, st.Image,
		r.Firmware, r.Config, time.Duration(st.UptimeS)*time.Second)
	if err := h.InService(nil); err != nil {
		r.Problems = append(r.Problems, err.Error())
	}
	if st.Reboot != nil && st.Reboot.Pending {
		r.Problems = append(r.Problems, "reboot pending ("+strings.Join(st.Reboot.Reasons, ", ")+")")
	}
	if st.Config != nil && st.Config.Trial {
		r.Problems = append(r.Problems, "config on trial")
	}
	if err := c.CheckDNS(ctx, n.Addr, *st, *h, fleet.Checks{Forwarded: []string{"example.com"}}); err != nil {
		r.Problems = append(r.Problems, "DNS: "+err.Error())
	}
	return r
}

func list(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}
