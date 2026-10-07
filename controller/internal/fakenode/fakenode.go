// Package fakenode is a fake espDNS node for tests and browser checks: its HTTP side
// (/status, /health, /release, /ota) and its DNS answers, as firmware/main serves them.
// It checks every release as the firmware does (signed by the key in slot 0, for its node
// ID and chip image, a seq above its last, the payload's hash) and takes firmware (staged,
// rebooted into, on trial, or rolled back), configs, hosted zones, blocklists, overrides
// and the control commands (a revert goes back to the list or overrides it held before, as
// the firmware's two slots do, live or at the next boot when two copies don't fit; each
// list blocks its own names, Lists). A reboot takes it down for a while. As the firmware, it
// answers only a request whose Host names it (its Addr, its .local name, or its config's name;
// else 421, httpguard.h), so the controller's requests are checked for that too. Nothing
// here reaches a network: the caller serves it (httptest, or a loopback address).
package fakenode

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// Node is one fake node. Set its fields before it serves; after, change them only under
// Lock (Do).
type Node struct {
	Name  string
	MAC   [6]byte
	Image string // chip image
	Board string
	Pub   []byte // the release key it trusts in slot 0
	Addr  string // where it is reached (host or host:port), for its "ip"
	// Firmware it runs.
	Version, Elf, Slot string
	// DownFor is how long a reboot takes; TrialFor how long a new build stays on trial.
	DownFor, TrialFor time.Duration
	// Rollback: a new build fails its trial, and the node comes back on the old one.
	Rollback bool
	// NoObserve: firmware from before /metrics and the query log (observe.go); QueryLogCap
	// is its query log's ring (0: QueryLogCapacity).
	NoObserve   bool
	QueryLogCap int
	obs         observe
	// Memory is /status "memory.board"; nil: firmware from before the memory plan.
	Memory *memplan.Board
	// HostedLimitKB is its hosted zones' limit.
	HostedLimitKB int
	// Off are services off in its config (/status "services").
	Off []string
	// Secondary are its secondary zones (/status "zones") while no pushed config names
	// them; none if nil. A zones release with one of them is refused, as the node does.
	Secondary []string
	// Forward are its forward zones (conditional forwarders) while no pushed config names
	// them; none if nil. A zones release with one of them is refused, as the node does.
	// Its /status says them ("forward_zones", each {"name", "forwarder"}), as the firmware.
	Forward []nodecfg.ForwardZone
	// Blocked are the names its blocklist blocks while it is on (the one it starts with, and
	// any pushed while Lists is nil).
	Blocked []string
	// Lists, if set, says the names a blocklist or overrides pushed to it blocks (k: which),
	// from its payload: each list keeps its own, so a revert brings back the old one's.
	// Overrides block their names whatever the blocklist; none without Lists.
	Lists func(k release.Kind, payload []byte) []string
	// NoList: it starts with no blocklist (never sent one), as a node new to blocking.
	NoList bool
	// ListReboot: a list, or a revert, doesn't fit next to the one in use (two copies don't
	// fit): stored, reboot pending "blocklist: size", in use from the next boot.
	ListReboot bool
	// Queries are its /status "queries" counters (total, servfail, dropped, ...).
	Queries release.QueryCounts
	// Unadopted: it runs on its board's settings (/status config source "defaults") until
	// a config is pushed, as a node not adopted yet.
	Unadopted bool
	// FellBack: it took config seq 5 once, which it refuses now: it runs its board's
	// settings, as a node in service whose config no longer loads (with Unadopted).
	FellBack bool
	// Prefix and Gateway go with its address in /status config (default 24 and 127.0.0.1).
	Prefix  int
	Gateway string

	mu       sync.Mutex
	boot     time.Time
	down     time.Time // down until
	trialEnd time.Time
	seq      map[string]uint64
	staged   string // the elf a reboot goes to
	stagedV  string
	pending  []string
	list     release.ListStatus
	ovr      release.ListStatus
	// the other slot of each: what a revert goes back to; nil while it holds none
	listPrev *release.ListStatus
	ovrPrev  *release.ListStatus
	// the names each list pushed blocks (Lists), by "<kind> <seq>"
	blocks map[string][]string
	// what waits for the next boot (ListReboot), by kind: a list or a revert
	atBoot map[release.Kind]func()
	// blocking paused until (espdns pause); a reboot ends it, as on the node
	pauseUntil time.Time
	hosted     release.HostedStatus
	hostedPrev *release.HostedStatus // the bundle in its other slot: what a revert goes back to
	cfg        *nodecfg.Config
	state      string
	reasons    []string
	events     []string
	// A pushed config that moves the node: where it comes up at the next reboot, on trial
	// until a DNS query reaches it there.
	moveTo   string
	moveGW   string
	movePfx  int
	trial    bool
	fromCfg  bool // its address is its config's
	defaults bool // no config pushed yet (Unadopted)
}

// New is a node with defaults: up an hour, firmware "1" elf 0000000000000001, healthy,
// blocking on with a list (seq 1), hosted zones on.
func New(name string, mac [6]byte, image, board string, pub []byte) *Node {
	return &Node{Name: name, MAC: mac, Image: image, Board: board, Pub: pub, Version: "1", Elf: "0000000000000001",
		Slot: "ota_0", DownFor: 50 * time.Millisecond, HostedLimitKB: 64, Blocked: []string{"ads.example", "doubleclick.net"}}
}

func (n *Node) init() {
	if n.seq != nil {
		return
	}
	n.boot = time.Now().Add(-time.Hour)
	n.seq = map[string]uint64{"firmware": 1, "config": 1, "zones": 1, "blocklist": 1, "overrides": 1, "control": 1}
	n.list = release.ListStatus{State: "on", Seq: 1, Entries: 1000, Tier: "ram", Bytes: 64 << 10, Slot: slot(0)}
	if n.NoList {
		n.list = release.ListStatus{State: "off", Slot: slot(-1)}
		n.seq["blocklist"] = 0
	}
	n.ovr = release.ListStatus{State: "off", Slot: slot(-1)}
	n.hosted = release.HostedStatus{State: "on", Seq: 1, LimitBytes: n.HostedLimitKB * 1024, Slot: slot(0)}
	n.cfg = &nodecfg.Config{Name: n.Name}
	n.state = "healthy"
	n.defaults = n.Unadopted
	if n.Unadopted {
		// A node never adopted has taken no config: its config seq is 0.
		n.seq["config"] = 0
		if n.FellBack {
			n.seq["config"] = 5
		}
	}
	if n.Prefix == 0 {
		n.Prefix = 24
	}
	if n.Gateway == "" {
		n.Gateway = "127.0.0.1"
	}
}

// Do runs f with the node locked, to change it while it serves.
func (n *Node) Do(f func(n *Node)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.init()
	f(n)
}

// Break makes the node unhealthy (state fault, not answering) or well again.
func (n *Node) Break(broken bool) {
	n.Do(func(n *Node) {
		if broken {
			n.state, n.reasons = "fault", []string{"dns"}
		} else {
			n.state, n.reasons = "healthy", nil
		}
	})
}

// SetPending makes the node wait for a reboot, for these reasons (as a release that
// needs one leaves it).
func (n *Node) SetPending(reasons ...string) { n.Do(func(n *Node) { n.pending = reasons }) }

// Events is what happened to the node, in order: "push <kind>", "reboot", "up".
func (n *Node) Events() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.events)
}

// ID is its node ID, as /status says it.
func (n *Node) ID() string {
	m := n.MAC
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// isDown says whether it is rebooting; it comes back on the staged build. Locked.
func (n *Node) isDown() bool {
	if n.down.IsZero() {
		return false
	}
	if time.Now().Before(n.down) {
		return true
	}
	n.down = time.Time{}
	n.boot = time.Now()
	n.events = append(n.events, "up")
	n.obsReboot()
	if n.staged != "" {
		if !n.Rollback {
			n.Elf, n.Version = n.staged, n.stagedV
			n.Slot = map[string]string{"ota_0": "ota_1", "ota_1": "ota_0"}[n.Slot]
			n.trialEnd = time.Now().Add(n.TrialFor)
		}
		n.staged = ""
	}
	n.pending = nil
	for k, f := range n.atBoot {
		f()
		delete(n.atBoot, k)
	}
	if n.moveTo != "" {
		// Up on the new address, on trial until it is reached there.
		n.Addr, n.Gateway, n.Prefix, n.moveTo = n.moveTo, n.moveGW, n.movePfx, ""
		n.trial, n.fromCfg = true, true
		n.events = append(n.events, "moved to "+n.Addr)
	}
	return false
}

func (n *Node) reboot() {
	n.events = append(n.events, "reboot")
	n.down = time.Now().Add(n.DownFor)
	n.pauseUntil = time.Time{} // a pause isn't kept across a reboot
}

func (n *Node) answering() bool { return n.state == "healthy" || n.state == "degraded" }

func (n *Node) otaState() string {
	if time.Now().Before(n.trialEnd) {
		return "trial"
	}
	return "valid"
}

func (n *Node) services() []map[string]any {
	var out []map[string]any
	for _, s := range n.serviceNames() {
		st := "running"
		if slices.Contains(n.Off, s) || s == "querylog" && !n.querylogOn() {
			st = "off"
		}
		out = append(out, map[string]any{"name": s, "state": st})
	}
	return out
}

func (n *Node) status() map[string]any {
	reasons := n.reasons
	if reasons == nil {
		reasons = []string{}
	}
	pending := n.pending
	if pending == nil {
		pending = []string{}
	}
	src, from, cseq := "node", "board", n.seq["config"]
	var cerr any
	if n.defaults {
		src, cseq = "defaults", 0
		if n.FellBack {
			cerr = "config seq 5 refused: memory plan: too big"
		}
	}
	if n.fromCfg {
		from = "config"
	}
	zs := []map[string]any{}
	for _, z := range n.secondary() {
		zs = append(zs, map[string]any{"name": z})
	}
	var hz []map[string]any
	for _, z := range n.hosted.Zones {
		hz = append(hz, map[string]any{"name": z.Name, "serial": z.Serial, "records": z.Records})
	}
	st := map[string]any{"project": "espdns", "version": n.Version, "built": "Oct  3 2026 12:00:00", "elf_sha256": n.Elf,
		"slot": n.Slot, "ota_state": n.otaState(), "uptime_s": int64(time.Since(n.boot).Seconds()), "node_id": n.ID(),
		"board": n.Board, "image": n.Image, "boot_ms": 2100, "ip": n.Addr,
		"keys": []string{release.Fingerprint(n.Pub), "1111111111111111"}, "seq": n.seq,
		"net":    map[string]any{"kind": "ethernet", "mac": n.ID(), "link": true, "hostname": n.Name + ".local"},
		"health": map[string]any{"state": n.state, "answering": n.answering(), "reasons": reasons},
		"reboot": map[string]any{"pending": len(n.pending) > 0, "reasons": pending, "since_s": 3},
		"config": map[string]any{"source": src, "seq": cseq, "error": cerr, "address": "static", "address_from": from,
			"ip": fmt.Sprintf("%s/%d", hostOnly(n.Addr), n.Prefix), "gateway": n.Gateway, "name": n.cfg.Name,
			"storage": "partition", "trial": n.trial},
		"zones": zs,
		"hosted": map[string]any{"state": n.hosted.State, "seq": n.hosted.Seq, "sha256": n.hosted.SHA256, "slot": n.hosted.Slot,
			"reverted_from": n.hosted.RevertedFrom, "bytes": n.hosted.Bytes, "limit_bytes": n.hosted.LimitBytes, "zones": hz},
		"services": n.services(),
		"blocking": map[string]any{"list": n.list, "overrides": n.ovr, "paused_s": n.pausedS()},
		"queries":  n.Queries,
	}
	n.observeStatus(st)
	if n.Memory != nil {
		st["memory"] = map[string]any{"board": n.Memory}
	}
	fz := []map[string]any{}
	for _, z := range n.forward() {
		fz = append(fz, map[string]any{"name": z.Zone, "forwarder": z.Forwarder})
	}
	st["forward_zones"] = fz
	return st
}

// forward are its forward zones: its pushed config's, else Forward. Locked.
func (n *Node) forward() []nodecfg.ForwardZone {
	if n.cfg.ForwardZones != nil {
		return *n.cfg.ForwardZones
	}
	return n.Forward
}

func slot(i int) *int { return &i }

// secondary are its secondary zones: its pushed config's, else Secondary. Locked.
func (n *Node) secondary() []string {
	if s := n.cfg.Secondary; s != nil && s.Zones != nil {
		return *s.Zones
	}
	return n.Secondary
}

func hostOnly(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

func (n *Node) health() map[string]any {
	return map[string]any{"state": n.state, "answering": n.answering(), "reasons": n.status()["health"].(map[string]any)["reasons"],
		"uptime_s":  int64(time.Since(n.boot).Seconds()),
		"blocklist": map[string]any{"state": n.list.State, "seq": n.list.Seq},
		"overrides": map[string]any{"state": n.ovr.State, "seq": n.ovr.Seq},
		"zones":     map[string]any{"state": n.hosted.State, "seq": n.hosted.Seq}}
}

// hostOK is the firmware's Host check (firmware/main/httpguard.h): the request names this
// node by its address, its mDNS name or its configured name, with or without a port.
// Without an Addr (a node a test reaches some other way) the address is not checked. Locked.
func (n *Node) hostOK(host string) bool {
	if host == "" || strings.HasPrefix(host, "[") {
		return false
	}
	h := strings.TrimSuffix(hostOnly(host), ".")
	switch {
	case h == "":
		return false
	case n.Addr == "" || h == hostOnly(n.Addr):
		return true
	case strings.EqualFold(h, n.Name+".local"):
		return true
	}
	return n.cfg.Name != "" && strings.EqualFold(h, n.cfg.Name)
}

// ServeHTTP is the node's HTTP side.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.init()
	if !n.hostOK(r.Host) {
		http.Error(w, "Host: this node's address or name only", http.StatusMisdirectedRequest)
		return
	}
	if n.isDown() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/status":
		json.NewEncoder(w).Encode(n.status())
	case "/health":
		if !n.answering() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(n.health())
	case "/release", "/ota":
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		reply, err := n.release(b, r.URL.Path == "/ota", r.Header.Get("X-OTA-Reboot") == "later")
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(reply)
	default:
		if !n.serveObserve(w, r) {
			http.NotFound(w, r)
		}
	}
}

// release checks a release as the firmware does and applies it. Locked.
func (n *Node) release(b []byte, ota, later bool) (map[string]any, error) {
	if len(b) < release.HeaderLen || !release.Verify(n.Pub, b[:release.HeaderLen]) {
		return nil, errors.New("signature not by a trusted key")
	}
	m, p := b[:release.ManifestLen], b[release.HeaderLen:]
	kind := release.Kind(m[8])
	seq := binary.LittleEndian.Uint64(m[32:])
	sum := sha256.Sum256(p)
	switch {
	case m[9] != release.KeyRelease:
		return nil, fmt.Errorf("key slot %d", m[9])
	case string(m[10:16]) != string(n.MAC[:]):
		return nil, errors.New("not for this node")
	case strings.TrimRight(string(m[16:32]), "\x00") != n.Image:
		return nil, errors.New("not for this chip image")
	case seq <= n.seq[kind.String()]:
		return nil, fmt.Errorf("seq %d not above %d", seq, n.seq[kind.String()])
	case binary.LittleEndian.Uint64(m[40:]) != uint64(len(p)) || string(sum[:]) != string(m[48:80]):
		return nil, errors.New("payload hash")
	case (kind == release.Firmware) != ota:
		return nil, errors.New("firmware goes to /ota, the rest to /release")
	}
	ok := func(msg string, pending bool) map[string]any {
		return map[string]any{"ok": true, "message": msg, "reboot_pending": pending || len(n.pending) > 0}
	}
	n.events = append(n.events, "push "+kind.String())
	switch kind {
	case release.Firmware:
		d, err := release.ParseAppDesc(p)
		if err != nil {
			return nil, err
		}
		n.seq["firmware"] = seq
		n.staged, n.stagedV = d.ElfSHA256, d.Version
		if later {
			n.pending = append(n.pending, "firmware")
			return ok(fmt.Sprintf("firmware seq %d staged; it boots at the next reboot", seq), true), nil
		}
		n.reboot()
		return map[string]any{"ok": true, "message": "rebooting", "rebooting": true}, nil
	case release.Config:
		c, err := nodecfg.Parse(p)
		if err == nil {
			err = n.observeConfig(c)
		}
		if err != nil {
			return nil, err
		}
		n.cfg, n.seq["config"], n.defaults = c, seq, false
		if c.Network != nil && c.Network.Address != "dhcp" {
			pfx, err := netip.ParsePrefix(c.Network.Address)
			if err != nil {
				return nil, err
			}
			if a := pfx.Addr().String(); a != hostOnly(n.Addr) || pfx.Bits() != n.Prefix || c.Network.Gateway != n.Gateway {
				if a == hostOnly(n.Addr) {
					// The same address, another network: applied live, as the firmware's
					// own network compare would not ask for a reboot for the address.
					n.Prefix, n.Gateway, n.fromCfg = pfx.Bits(), c.Network.Gateway, true
					return ok(fmt.Sprintf("config seq %d applied live", seq), false), nil
				}
				n.moveTo, n.moveGW, n.movePfx = a, c.Network.Gateway, pfx.Bits()
				if !slices.Contains(n.pending, nodecfg.ReasonAddress) {
					n.pending = append(n.pending, nodecfg.ReasonAddress)
				}
				return ok(fmt.Sprintf("config seq %d stored: the new address waits for a reboot (on trial)", seq), true), nil
			}
			n.fromCfg = true
		}
		return ok(fmt.Sprintf("config seq %d applied live", seq), false), nil
	case release.Zones:
		set, err := zones.ParseBundle(p)
		if err != nil {
			return nil, err
		}
		if len(p) > n.hosted.LimitBytes {
			return nil, errors.New("zones over the limit")
		}
		names := slices.Clone(n.secondary())
		for _, f := range n.forward() {
			names = append(names, f.Zone)
		}
		for _, z := range set.Zones {
			for _, sz := range names {
				if strings.EqualFold(strings.TrimSuffix(sz, "."), z.Name()) {
					return nil, fmt.Errorf("zones refused: %s is a secondary or forward zone in the node config", z.Name())
				}
			}
		}
		n.seq["zones"] = seq
		// Into the slot not in use; the bundle in use becomes the older copy.
		n.hostedPrev = nil
		if n.hosted.State == "on" {
			old := n.hosted
			n.hostedPrev = &old
		}
		to := 0
		if n.hosted.Slot != nil && *n.hosted.Slot == 0 {
			to = 1
		}
		h := release.HostedStatus{State: "on", Seq: seq, Bytes: len(p), LimitBytes: n.hosted.LimitBytes, Slot: slot(to),
			SHA256: hex.EncodeToString(sum[:])}
		for _, z := range set.Zones {
			h.Zones = append(h.Zones, struct {
				Name    string `json:"name"`
				Serial  uint32 `json:"serial"`
				Records int    `json:"records"`
			}{z.Name(), z.Serial(), len(z.Records)})
		}
		n.hosted = h
		return ok(fmt.Sprintf("zones seq %d applied live", seq), false), nil
	case release.Blocklist, release.Overrides:
		need, err := blocklist.PlanNeed(p, int64(len(p)))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(p)
		l := release.ListStatus{State: "on", Seq: seq, Entries: need.Entries, Tier: "ram", Bytes: int64(len(p)), SHA256: hex.EncodeToString(sum[:])}
		n.seq[kind.String()] = seq
		if n.Lists != nil {
			if n.blocks == nil {
				n.blocks = map[string][]string{}
			}
			n.blocks[fmt.Sprint(kind, " ", seq)] = n.Lists(kind, p)
		}
		cur, prev := n.lists(kind)
		// Into the slot not in use; the one in use becomes the older copy.
		l.Slot = slot(0)
		if cur.Slot != nil && *cur.Slot == 0 {
			l.Slot = slot(1)
		}
		swap := func() {
			*prev = nil
			if cur.State == "on" {
				old := *cur
				*prev = &old
			}
			*cur = l
		}
		if n.ListReboot {
			n.later(kind, swap)
			return ok(fmt.Sprintf("%s seq %d stored: it loads at the next boot (two copies don't fit)", kind, seq), true), nil
		}
		swap()
		return ok(fmt.Sprintf("%s seq %d applied live", kind, seq), false), nil
	case release.Control:
		if len(p) == 2 && p[0] == 5 {
			// Revert, refused before its seq is taken when there is nothing older to go to.
			k := release.Kind(p[1])
			if k == release.Zones {
				msg, err := n.revertZones(seq)
				if err != nil {
					return nil, err
				}
				return ok(msg, false), nil
			}
			if k != release.Blocklist && k != release.Overrides {
				return nil, errors.New("bad revert payload")
			}
			cur, prev := n.lists(k)
			switch {
			case slices.Contains(n.Off, "blocking"):
				return nil, errors.New("blocking is off in the node config")
			case n.atBoot[k] != nil:
				return nil, fmt.Errorf("a %s waits for the next boot: nothing older to revert to", fileName(k))
			case cur.State != "on":
				return nil, fmt.Errorf("no %s in use: nothing to revert from", fileName(k))
			case *prev == nil:
				return nil, fmt.Errorf("no previous %s to revert to: slot %d is empty", fileName(k), 1-*cur.Slot)
			case (*prev).Seq >= cur.Seq:
				return nil, fmt.Errorf("no previous %s to revert to: slot %d holds seq %d, not older than seq %d in use (reverted from)",
					fileName(k), *(*prev).Slot, (*prev).Seq, cur.Seq)
			}
			n.seq["control"] = seq
			from, to := *cur, **prev
			to.RevertedFrom, from.RevertedFrom = from.Seq, 0
			if n.ListReboot {
				n.later(k, func() { *cur, *prev = to, &from })
				return ok(fmt.Sprintf("%s revert to seq %d (slot %d) stored: it loads at the next boot (two copies don't fit)",
					fileName(k), to.Seq, *to.Slot), true), nil
			}
			*cur, *prev = to, &from
			return ok(fmt.Sprintf("%s reverted to seq %d (slot %d) from seq %d: %d entries, RAM tier", fileName(k), to.Seq,
				*to.Slot, from.Seq, to.Entries), false), nil
		}
		n.seq["control"] = seq
		if len(p) == 5 && p[0] == 1 {
			// Pause, as the firmware: for the seconds given from now, 0 resumes.
			secs := binary.LittleEndian.Uint32(p[1:])
			if secs == 0 {
				n.pauseUntil = time.Time{}
				return ok("ok, blocking resumed", false), nil
			}
			n.pauseUntil = time.Now().Add(time.Duration(secs) * time.Second)
			return ok(fmt.Sprintf("ok, blocking paused for %d s", secs), false), nil
		}
		if len(p) == 0 || p[0] != 4 {
			return ok("ok", false), nil
		}
		if len(p) > 5 && p[5] == 1 && len(n.pending) == 0 {
			return ok("no reboot pending: not rebooting", false), nil
		}
		n.reboot()
		return map[string]any{"ok": true, "message": "rebooting", "rebooting": true}, nil
	}
	return nil, fmt.Errorf("kind %v", kind)
}

// revertZones sends the hosted zones back to the bundle in the other slot, live, as the
// firmware (hosted.c): refused before the control seq is taken when there is nothing older.
// Locked.
func (n *Node) revertZones(seq uint64) (string, error) {
	cur, prev := n.hosted, n.hostedPrev
	switch {
	case slices.Contains(n.Off, "hosted"):
		return "", errors.New("hosted zones are off in the node config")
	case cur.State != "on":
		return "", errors.New("no zones in use: nothing to revert from")
	case prev == nil:
		return "", fmt.Errorf("no previous zones to revert to: slot %d is empty", 1-*cur.Slot)
	case prev.Seq >= cur.Seq:
		why := "newer"
		if prev.Seq == cur.RevertedFrom {
			why = "reverted from"
		}
		return "", fmt.Errorf("no previous zones to revert to: slot %d holds seq %d, not older than seq %d in use (%s)",
			*prev.Slot, prev.Seq, cur.Seq, why)
	}
	n.seq["control"] = seq
	from, to := cur, *prev
	to.RevertedFrom, from.RevertedFrom = from.Seq, 0
	n.hosted, n.hostedPrev = to, &from
	return fmt.Sprintf("zones reverted to seq %d (slot %d) from seq %d: %d zones", to.Seq, *to.Slot, from.Seq,
		len(to.Zones)), nil
}

// later keeps f, the list of kind k loaded (or reverted), for the next boot: reboot pending
// "blocklist: size", as the node waits when two copies don't fit. Locked.
func (n *Node) later(k release.Kind, f func()) {
	if n.atBoot == nil {
		n.atBoot = map[release.Kind]func(){}
	}
	n.atBoot[k] = f
	if !slices.Contains(n.pending, "blocklist: size") {
		n.pending = append(n.pending, "blocklist: size")
	}
}

// blocks says whether the node blocks name now: its blocklist's names while it is on, its
// overrides' while they are on. Locked.
func (n *Node) isBlocked(name string) bool {
	if n.pausedS() > 0 {
		return false
	}
	names := func(k release.Kind, l release.ListStatus, dflt []string) []string {
		if l.State != "on" {
			return nil
		}
		if b, ok := n.blocks[fmt.Sprint(k, " ", l.Seq)]; ok {
			return b
		}
		return dflt
	}
	return slices.Contains(names(release.Blocklist, n.list, n.Blocked), name) ||
		slices.Contains(names(release.Overrides, n.ovr, nil), name)
}

// pausedS is how long blocking stays paused, as /status says it. Locked.
func (n *Node) pausedS() uint32 {
	if d := time.Until(n.pauseUntil); d > 0 {
		return uint32((d + time.Second - 1) / time.Second)
	}
	return 0
}

// lists are the list of kind k (blocklist or overrides) in use, and the older copy in its
// other slot. Locked.
func (n *Node) lists(k release.Kind) (*release.ListStatus, **release.ListStatus) {
	if k == release.Overrides {
		return &n.ovr, &n.ovrPrev
	}
	return &n.list, &n.listPrev
}

// fileName is the firmware's name for a list kind in its replies ("list", "overrides").
func fileName(k release.Kind) string {
	if k == release.Overrides {
		return "overrides"
	}
	return "list"
}

// Answer is the node's DNS answer to m; nil while it doesn't answer.
func (n *Node) Answer(m *dns.Msg) *dns.Msg {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.init()
	if n.isDown() || !n.answering() || len(m.Question) == 0 {
		return nil
	}
	n.trial = false // reached: a config on trial is kept
	q := m.Question[0]
	r := new(dns.Msg)
	r.SetReply(m)
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	switch {
	case q.Qtype == dns.TypeSOA:
		r.Authoritative = true
		rr, _ := dns.NewRR(q.Name + " 60 IN SOA ns. host. 1 60 60 60 60")
		r.Answer = append(r.Answer, rr)
	case slices.Contains(n.Off, "forwarding"):
		r.Rcode = dns.RcodeRefused
	case strings.HasSuffix(name, ".invalid"):
		r.Rcode = dns.RcodeNameError
	case n.isBlocked(name):
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A: net.IPv4zero})
	default:
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A: net.IPv4(192, 0, 2, 1)})
	}
	return r
}

// Net is fake nodes found by the address each is on now (one that moves is found on its
// new address): their DNS side as a fleet.Resolver.
type Net []*Node

// At is the node on host now (its Addr, without a port), nil if none.
func (ns Net) At(host string) *Node {
	h := hostOnly(host)
	for _, n := range ns {
		n.mu.Lock()
		a := hostOnly(n.Addr)
		n.mu.Unlock()
		if a == h {
			return n
		}
	}
	return nil
}

// Exchange answers as the node on host now does.
func (ns Net) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	n := ns.At(host)
	if n == nil {
		return nil, errors.New("timeout")
	}
	if r := n.Answer(m); r != nil {
		return r, nil
	}
	return nil, errors.New("timeout")
}

// Fleet is fake nodes by address: their DNS side as a fleet.Resolver.
type Fleet map[string]*Node

// Exchange answers as the node at host does.
func (f Fleet) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	n := f[host]
	if n == nil {
		return nil, errors.New("timeout")
	}
	r := n.Answer(m)
	if r == nil {
		return nil, errors.New("timeout")
	}
	return r, nil
}

// App is a firmware image whose app descriptor says version and elf (16 hex digits),
// built Oct  3 2026 12:00:00 (the fake node's /status "built").
func App(version, elf string) []byte { return AppBuilt(version, elf, "Oct  3 2026", "12:00:00") }

// AppBuilt is App built on date ("Oct  7 2026", as __DATE__) at clock ("12:00:00").
func AppBuilt(version, elf, date, clock string) []byte {
	b := make([]byte, 4096)
	b[0] = 0xE9
	binary.LittleEndian.PutUint32(b[32:], 0xABCD5432)
	copy(b[32+16:], version)
	copy(b[32+48:], "espdns")
	copy(b[32+80:], clock)
	copy(b[32+96:], date)
	e, err := hex.DecodeString(elf)
	if err != nil || len(e) != 8 {
		panic("fakenode.App: elf is 16 hex digits")
	}
	copy(b[32+144:], e)
	return b
}
