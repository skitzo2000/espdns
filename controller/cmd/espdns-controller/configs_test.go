package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/configs"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/nodes"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

var macs atomic.Uint32

// cfgNode is a fake node that takes config releases as the firmware does: signed by the
// release key for its node ID and chip image, a seq above its last; a config that changes
// only what applies live is applied at once, one that changes the address, the Wi-Fi
// network or the zones (nodecfg.Compare, the firmware's reasons) is stored and waits for
// the reboot command. A reboot takes it down for a moment; on a new address it comes up on
// trial there, confirmed once it is reached.
type cfgNode struct {
	t        *testing.T
	pub      []byte
	mac      [6]byte
	addr     string
	mu       sync.Mutex
	healthy  bool
	down     bool
	boot     time.Time
	cfg      *nodecfg.Config
	seq      map[string]uint64
	pending  *nodecfg.Config
	pendSeq  uint64
	reasons  []string
	trial    bool
	ip       string // the static address it reports, prefix length included
	services bool   // firmware with services (and "cpu")
	source   string // /status config source: "node" (a pushed config) or "defaults"
	memory   *memplan.Board
	got      []string
}

func newCfgNode(t *testing.T, key *ecdsa.PrivateKey) *cfgNode {
	n := &cfgNode{t: t, pub: release.PublicRaw(key), healthy: true, boot: time.Now().Add(-time.Hour), services: true,
		cfg: &nodecfg.Config{}, seq: map[string]uint64{"config": 1, "control": 1}, ip: "192.0.2.250/23", source: "node"}
	m := macs.Add(1)
	n.mac = [6]byte{0x30, 0xed, 0xa0, 0, byte(m >> 8), byte(m)}
	srv := httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(srv.Close)
	n.addr = strings.TrimPrefix(srv.URL, "http://")
	return n
}

func (n *cfgNode) id() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5])
}

// ifaceMAC is the MAC of the interface it uses, as /status net.mac has it: on an ESP32 the
// Ethernet's is the chip's (its ID) plus 3.
func (n *cfgNode) ifaceMAC() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5]+3)
}

func (n *cfgNode) took() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.got)
}

func (n *cfgNode) serve(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	state := "healthy"
	if !n.healthy {
		state = "fault"
	}
	switch r.URL.Path {
	case "/status":
		st := map[string]any{"node_id": n.id(), "image": "esp32s3-octal", "board": "ws-s3-eth",
			"keys": []string{release.Fingerprint(n.pub), "0000000000000000"}, "seq": n.seq,
			"uptime_s": int64(time.Since(n.boot).Seconds()), "net": map[string]any{"kind": "ethernet", "mac": n.ifaceMAC()},
			"config": map[string]any{"source": n.source, "seq": n.seq["config"], "address": "static", "ip": n.ip,
				"gateway": "192.0.2.1", "address_from": "board", "name": n.cfg.Name, "trial": n.trial},
			"health": map[string]any{"state": state, "answering": n.healthy, "reasons": []string{}},
			"reboot": map[string]any{"pending": n.pending != nil, "reasons": n.reasons}}
		if n.services {
			st["services"] = []map[string]any{{"name": "dns", "state": "running"}}
			st["cpu"] = map[string]any{"dfs": true, "from": "image", "max_mhz": 240, "min_mhz": 80}
		}
		if n.memory != nil {
			st["memory"] = map[string]any{"board": n.memory}
		}
		json.NewEncoder(w).Encode(st)
		// Reached on its new address: the trial is over (the firmware: a DNS query there).
		n.trial = false
	case "/health":
		code := http.StatusOK
		if !n.healthy {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{"state": state, "answering": n.healthy, "reasons": []string{}})
	case "/release":
		body, _ := io.ReadAll(r.Body)
		reply, err := n.release(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(reply)
	default:
		http.NotFound(w, r)
	}
}

func (n *cfgNode) release(b []byte) (map[string]any, error) {
	if len(b) < release.HeaderLen || !release.Verify(n.pub, b[:release.HeaderLen]) {
		return nil, fmt.Errorf("bad signature")
	}
	m, payload := b[:release.ManifestLen], b[release.HeaderLen:]
	kind := release.Kind(m[8])
	seq := binary.LittleEndian.Uint64(m[32:])
	sum := sha256.Sum256(payload)
	switch {
	case m[9] != release.KeyRelease:
		return nil, fmt.Errorf("key %d", m[9])
	case string(m[10:16]) != string(n.mac[:]) || strings.TrimRight(string(m[16:32]), "\x00") != "esp32s3-octal":
		return nil, fmt.Errorf("not for this node")
	case seq <= n.seq[kind.String()]:
		return nil, fmt.Errorf("seq %d not above %d", seq, n.seq[kind.String()])
	case binary.LittleEndian.Uint64(m[40:]) != uint64(len(payload)) || string(sum[:]) != string(m[48:80]):
		return nil, fmt.Errorf("payload hash")
	}
	switch kind {
	case release.Config:
		c, err := nodecfg.Parse(payload)
		if err != nil {
			return nil, err
		}
		if !n.services && (c.SwitchesServices() || c.SetsCPU()) {
			return nil, fmt.Errorf("unknown setting")
		}
		n.got = append(n.got, fmt.Sprintf("config %d", seq))
		ch := nodecfg.Compare(n.cfg, c, nil)
		if reasons := append(ch.Reboot, ch.Maybe...); len(reasons) > 0 {
			n.pending, n.pendSeq, n.reasons = c, seq, reasons
			return map[string]any{"ok": true, "message": fmt.Sprintf("config seq %d stored", seq), "reboot_pending": true}, nil
		}
		n.cfg, n.seq["config"], n.source = c, seq, "node"
		return map[string]any{"ok": true, "message": fmt.Sprintf("config seq %d applied live", seq)}, nil
	case release.Control:
		n.seq["control"] = seq
		if payload[0] != 4 {
			return nil, fmt.Errorf("command %d", payload[0])
		}
		if payload[5] == 1 && n.pending == nil {
			n.got = append(n.got, "reboot refused: none pending")
			return map[string]any{"ok": true, "message": "no reboot pending"}, nil
		}
		n.got = append(n.got, "reboot")
		n.down = true
		go func() {
			time.Sleep(150 * time.Millisecond)
			n.mu.Lock()
			defer n.mu.Unlock()
			if n.pending != nil {
				if a, ok := n.pending.StaticAddr(); ok && n.pending.Network.Address != n.ip {
					n.ip, n.trial = n.pending.Network.Address, a.IsValid()
				}
				n.cfg, n.seq["config"], n.pending, n.reasons, n.source = n.pending, n.pendSeq, nil, nil, "node"
			}
			n.down, n.boot = false, time.Now()
		}()
		return map[string]any{"ok": true, "message": "rebooting", "rebooting": true}, nil
	}
	return nil, fmt.Errorf("kind %v", kind)
}

// pushEnv is a data directory with settings, configs and a runner with the config-push kind.
type pushEnv struct {
	t      *testing.T
	dir    string
	key    *ecdsa.PrivateKey
	runner *jobs.Runner
	http   *http.Client
}

func newPushEnv(t *testing.T, k *ecdsa.PrivateKey, s settings.Settings, cfgs map[string]string, hc *http.Client) *pushEnv {
	dir := t.TempDir()
	if err := settings.Save(settings.Path(dir), s); err != nil {
		t.Fatal(err)
	}
	for name, text := range cfgs {
		if _, err := configs.Save(dir, name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range s.Nodes { // adopted: pinned
		pinAt(t, dir, h)
	}
	a := answers{asked: make(chan string, 1000)}
	e := &pushEnv{t: t, dir: dir, key: k, http: hc}
	act := actions{dataDir: dir, key: keyOf{k}, known: func() []string { return s.Nodes },
		client: func() *fleet.Client {
			return &fleet.Client{DNS: a, PeerDNS: a, Poll: 20 * time.Millisecond, HTTP: hc}
		}}
	push := configPush{actions: act, catalog: "../../../boards", secret: newSecret(),
		job: func(id string) (jobs.Job, bool) { return e.runner.Get(id) }}
	e.runner = jobs.New(dir, map[string]jobs.Kind{"config-push": push.kind})
	e.runner.Logf = t.Logf
	runJobs(t, e.runner)
	return e
}

// run queues a config-push and waits for it to end.
func (e *pushEnv) run(params string) (jobs.Job, error) {
	j, err := e.runner.Start("config-push", "admin", json.RawMessage(params))
	if err != nil {
		return j, err
	}
	for range 2000 {
		if j, _ = e.runner.Get(j.ID); j.State.Ended() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return j, nil
}

func logText(j jobs.Job) string {
	var b strings.Builder
	for _, l := range j.Log {
		b.WriteString(l.Text + "\n")
	}
	return b.String()
}

func params(node, config string, dry bool, after string) string {
	b, _ := json.Marshal(pushParams{Node: node, Config: config, DryRun: dry, After: after})
	return string(b)
}

// A config that changes only what applies live: a dry run (nothing pushed), then the push
// after it, applied live, checked, recorded.
func TestConfigPushLive(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	n.source = "defaults" // no config pushed yet: its settings are the firmware's
	e := newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}},
		map[string]string{"a.json": `{"name":"a","forwarders":["9.9.9.9"]}`, "b.json": `{"name":"b"}`}, nil)

	if _, err := e.run(params(n.addr, "a.json", false, "")); err == nil || !strings.Contains(err.Error(), "dry run first") {
		t.Fatalf("a push without a dry run: %v", err)
	}
	dry, err := e.run(params(n.addr, "a.json", true, ""))
	if err != nil || dry.State != jobs.Done {
		t.Fatalf("dry run: %+v %v\n%s", dry, err, logText(dry))
	}
	if len(n.took()) != 0 || !strings.Contains(logText(dry), "would push config") || !strings.Contains(logText(dry), "applies live: name, forwarders") {
		t.Fatalf("dry run: took %v\n%s", n.took(), logText(dry))
	}
	// The fingerprint is no hash of the file alone.
	if strings.Contains(string(dry.Result), configs.Hash([]byte(`{"name":"a","forwarders":["9.9.9.9"]}`))) {
		t.Error("the file's hash in the job record")
	}
	// A dry run for another node, or of another file, doesn't stand for this push.
	other, _ := e.run(params(n.addr, "b.json", true, ""))
	if other.State != jobs.Done {
		t.Fatalf("b.json: %+v", other)
	}
	if _, err := e.run(params(n.addr, "a.json", false, other.ID)); err == nil || !strings.Contains(err.Error(), "was for") {
		t.Errorf("another node's dry run: %v", err)
	}
	j, err := e.run(params(n.addr, "a.json", false, dry.ID))
	if err != nil || j.State != jobs.Done {
		t.Fatalf("push: %+v %v\n%s", j, err, logText(j))
	}
	if got := n.took(); len(got) != 1 || !strings.HasPrefix(got[0], "config ") || len(peer.took()) != 0 {
		t.Fatalf("took %v, peer %v", got, peer.took())
	}
	var res pushResult
	json.Unmarshal(j.Result, &res)
	if !res.Done || res.Seq == 0 || res.DryRun || !strings.Contains(logText(j), "applied live") {
		t.Fatalf("%+v\n%s", res, logText(j))
	}
	p, err := configs.LoadPushed(e.dir, n.id())
	if err != nil || p == nil || p.Seq != res.Seq || p.File != "a.json" || p.By != "controller" {
		t.Fatalf("recorded %+v %v", p, err)
	}
	// The editor: the node runs the file as saved.
	f, _ := configs.Read(e.dir, "a.json")
	st, _ := (&fleet.Client{}).Status(context.Background(), n.addr)
	if r := configs.NodeRuns(e.dir, "a.json", &f, st); r.State != "file" {
		t.Errorf("runs %+v", r)
	}
	// The action log: the jobs, with their params (no config text).
	es, _ := actionlog.Tail(e.dir, 0)
	for _, en := range es {
		if en.Action != "job config-push" || len(en.Args) != 1 || strings.Contains(en.Args[0], "forwarders") {
			t.Errorf("action log %+v", en)
		}
	}
	// The file changed since the dry run: no push.
	dry2, _ := e.run(params(n.addr, "a.json", true, ""))
	configs.Save(e.dir, "a.json", []byte(`{"name":"a","forwarders":["1.1.1.1"]}`), f.Hash)
	if _, err := e.run(params(n.addr, "a.json", false, dry2.ID)); err == nil || !strings.Contains(err.Error(), "changed since the dry run") {
		t.Errorf("changed file: %v", err)
	}
}

// A config that needs a reboot: pushed, the node waits, and is rebooted coordinated (while
// the other node answers), then checked on the new config.
func TestConfigPushReboot(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	n.source = "defaults"
	e := newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}},
		map[string]string{"z.json": `{"secondary":{"zones":["x.example"]}}`}, nil)
	dry, _ := e.run(params(n.addr, "z.json", true, ""))
	if dry.State != jobs.Done || !strings.Contains(logText(dry), "may need a reboot: config: zones") {
		t.Fatalf("%+v\n%s", dry, logText(dry))
	}
	j, _ := e.run(params(n.addr, "z.json", false, dry.ID))
	if j.State != jobs.Done {
		t.Fatalf("%+v\n%s", j, logText(j))
	}
	got := n.took()
	if len(got) != 2 || !strings.HasPrefix(got[0], "config ") || got[1] != "reboot" {
		t.Fatalf("took %v", got)
	}
	if !strings.Contains(logText(j), "reboot pending; rebooting it now") || !strings.Contains(logText(j), "checks passed") {
		t.Fatalf("%s", logText(j))
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pending != nil || n.cfg.Secondary == nil {
		t.Fatalf("the node runs %+v, pending %+v", n.cfg, n.pending)
	}
}

// The safety rule and the refusals: nothing pushed.
func TestConfigPushRefused(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	old := newCfgNode(t, k)
	old.services = false
	cfgs := map[string]string{"z.json": `{"secondary":{"zones":["x.example"]}}`, "off.json": `{"hosted":{"enabled":false}}`,
		"cpu.json": `{"cpu":{"dfs":false}}`, "a.json": `{"name":"a"}`}

	// Only the nodes in settings.json.
	e := newPushEnv(t, k, settings.Settings{Nodes: []string{peer.addr}}, cfgs, nil)
	if _, err := e.run(params(n.addr, "a.json", true, "")); err == nil || !strings.Contains(err.Error(), "not in settings.json") {
		t.Errorf("unlisted: %v", err)
	}
	for _, p := range []string{`{"node":"` + peer.addr + `","config":"nope.json","dry_run":true}`,
		`{"node":"` + peer.addr + `","config":"../a.json","dry_run":true}`, `{"node":"` + peer.addr + `"}`,
		`{"node":"` + peer.addr + `","config":"a.json","dry_run":true,"after":"x"}`,
		`{"node":"` + peer.addr + `","config":"a.json","x":1}`} {
		if _, err := e.run(p); err == nil {
			t.Errorf("%s queued", p)
		}
	}

	// The only node: a reboot would leave no node answering.
	e = newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr}}, cfgs, nil)
	j, _ := e.run(params(n.addr, "a.json", true, ""))
	if j.State != jobs.Failed || !strings.Contains(j.Error, "only node") {
		t.Errorf("the only node: %+v", j)
	}
	// The other node unhealthy: the last healthy node.
	peer.mu.Lock()
	peer.healthy = false
	peer.mu.Unlock()
	e = newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, cfgs, nil)
	j, _ = e.run(params(n.addr, "z.json", true, ""))
	if j.State != jobs.Failed || !strings.Contains(j.Error, "last healthy node") {
		t.Errorf("the last healthy node: %+v", j)
	}
	peer.mu.Lock()
	peer.healthy = true
	peer.mu.Unlock()

	// Firmware without services or clock scaling: refused before anything is pushed.
	e = newPushEnv(t, k, settings.Settings{Nodes: []string{old.addr, peer.addr}}, cfgs, nil)
	for cfg, want := range map[string]string{"off.json": "turns services on or off", "cpu.json": `sets "cpu"`} {
		j, _ := e.run(params(old.addr, cfg, true, ""))
		if j.State != jobs.Failed || !strings.Contains(j.Error, want) {
			t.Errorf("%s on old firmware: %+v", cfg, j)
		}
	}
	// A memory plan that doesn't fit the node: refused.
	small := memplan.Values(memplan.Keys{}, "esp32s3-octal", 8192)
	small.BlocklistKB = 4096
	n.memory = &small
	e = newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, cfgs, nil)
	j, _ = e.run(params(n.addr, "a.json", true, ""))
	if j.State != jobs.Failed || !strings.Contains(j.Error, "don't fit") {
		t.Errorf("memory: %+v", j)
	}
	// No release key: a dry run goes on, a push isn't queued.
	n.memory = nil
	e = newPushEnv(t, nil, settings.Settings{Nodes: []string{n.addr, peer.addr}}, cfgs, nil)
	if j, _ := e.run(params(n.addr, "a.json", true, "")); j.State != jobs.Done {
		t.Errorf("a dry run without a key: %+v", j)
	}
	if _, err := e.run(params(n.addr, "a.json", false, "x")); err == nil || !strings.Contains(err.Error(), "no release key") {
		t.Errorf("a push without a key: %v", err)
	}
	for _, x := range []*cfgNode{n, peer, old} {
		if len(x.took()) != 0 {
			t.Errorf("%s took %v", x.addr, x.took())
		}
	}
}

// A config that moves the node: pushed, the node rebooted onto the new address
// (coordinated), and confirmed there, as espdns config -reboot does.
func TestConfigPushMove(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	// The new address reaches the fake node.
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "192.0.2.9:") {
				addr = n.addr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	e := newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}},
		map[string]string{"m.json": `{"name":"m","network":{"address":"192.0.2.9/23","gateway":"192.0.2.1"}}`}, hc)
	dry, _ := e.run(params(n.addr, "m.json", true, ""))
	if dry.State != jobs.Done || !strings.Contains(logText(dry), "moves "+n.addr+" to 192.0.2.9") ||
		!strings.Contains(logText(dry), "would reboot now") || len(n.took()) != 0 {
		t.Fatalf("%+v\n%s", dry, logText(dry))
	}
	j, _ := e.run(params(n.addr, "m.json", false, dry.ID))
	if j.State != jobs.Done {
		t.Fatalf("%+v\n%s", j, logText(j))
	}
	if got := n.took(); len(got) != 2 || got[1] != "reboot" || !strings.Contains(logText(j), "confirmed") ||
		!strings.Contains(logText(j), "settings.json still lists") {
		t.Fatalf("took %v\n%s", got, logText(j))
	}
	if p, _ := configs.LoadPushed(e.dir, n.id()); p == nil || p.Host != "192.0.2.9" {
		t.Errorf("recorded %+v", p)
	}
	// Its pin moved with it: releases for 192.0.2.9 are signed for it, none for the old address.
	l := pins.Open(e.dir)
	if id, err := l.Pinned("192.0.2.9"); err != nil || id != n.id() {
		t.Errorf("pinned at the new address: %q %v", id, err)
	}
	if _, err := l.Pinned(n.addr); !errors.Is(err, pins.ErrNotPinned) {
		t.Errorf("the old address: %v", err)
	}
}

// The config API: a login needed for every route; the password never in a reply but the
// reveal; a save checked, kept, in the action log by the settings it changed.
func TestConfigsAPI(t *testing.T) {
	dir := t.TempDir()
	if err := auth.SetPassword(auth.Path(dir), "admin", testPassword); err != nil {
		t.Fatal(err)
	}
	k := newTestKey(t)
	node := newCfgNode(t, k)
	text := "{\n  \"name\": \"w\",\n  \"wifi\": { \"ssid\": \"home\", \"password\": \"hunter2hunter2\" }\n}\n"
	if _, err := configs.Save(dir, "w.json", []byte(text), ""); err != nil {
		t.Fatal(err)
	}
	st, err := (&fleet.Client{}).Status(context.Background(), node.addr)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(raw, &m)
	s := &server{dataDir: dir, auth: auth.New(auth.Path(dir)), runner: jobs.New(dir, map[string]jobs.Kind{}),
		key: keys.FileSource{Path: keys.Path(dir)}, builder: newBuilder(t.TempDir(), t.TempDir(), t.TempDir()), catalog: "../../../boards",
		nodes: func() []nodes.Node { return []nodes.Node{{Addr: node.addr, ID: node.id(), Online: true, Status: m}} }}
	h, _ := s.handler()
	cookie, tok := login(t, h)
	do := func(method, path, body string) (int, string) {
		r := httptest.NewRequest(method, "http://127.0.0.1:8480"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8480")
		r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
		r.Header.Set(auth.TokenHeader, tok)
		w := serve(h, r)
		return w.Code, w.Body.String()
	}
	code, b := do("GET", "/api/configs", "")
	if code != 200 || strings.Contains(b, "hunter2") || !strings.Contains(b, `"name":"w.json"`) || !strings.Contains(b, `"password":true`) {
		t.Fatalf("list: %d %s", code, b)
	}
	code, b = do("GET", "/api/configs/w.json", "")
	var got struct {
		Text, Hash string
		Password   bool
	}
	json.Unmarshal([]byte(b), &got)
	if code != 200 || strings.Contains(b, "hunter2") || !got.Password || !strings.Contains(got.Text, configs.Hidden) {
		t.Fatalf("get: %d %s", code, b)
	}
	// The reveal needs the password again (#68): refused without a grant, shown with one,
	// a grant good once.
	if code, b := do("GET", "/api/configs/w.json?reveal=1", ""); code != http.StatusForbidden || strings.Contains(b, "hunter2") ||
		!strings.Contains(b, `"reauth":true`) {
		t.Errorf("reveal without a grant: %d %s", code, b)
	}
	reveal := func(grant string) (int, string) {
		r := withSession(httptest.NewRequest("GET", "http://127.0.0.1:8480/api/configs/w.json?reveal=1", nil), cookie, tok)
		r.Header.Set(auth.ReauthHeader, grant)
		w := serve(h, r)
		return w.Code, w.Body.String()
	}
	if code, b := reveal("made up"); code != http.StatusForbidden || strings.Contains(b, "hunter2") {
		t.Errorf("reveal with a made-up grant: %d %s", code, b)
	}
	g := reauth(t, h, cookie, tok)
	if code, b := reveal(g); code != 200 || !strings.Contains(b, "hunter2hunter2") || !strings.Contains(b, `"revealed":true`) {
		t.Errorf("reveal: %d %s", code, b)
	}
	if code, b := reveal(g); code != http.StatusForbidden || strings.Contains(b, "hunter2") {
		t.Errorf("reveal with a used grant: %d %s", code, b)
	}
	if code, _ := do("GET", "/api/configs/nope.json", ""); code != 404 {
		t.Errorf("missing: %d", code)
	}
	// The check: on the node, the password kept as saved (no change), never in the reply.
	req, _ := json.Marshal(map[string]string{"text": strings.Replace(got.Text, `"w"`, `"w2"`, 1), "node": node.addr})
	code, b = do("POST", "/api/configs/w.json/check", string(req))
	var ck configs.Result
	json.Unmarshal([]byte(b), &ck)
	if code != 200 || strings.Contains(b, "hunter2") || !ck.OK || ck.Node == nil || !slices.Contains(ck.Node.Change.Live, "name") ||
		slices.Contains(ck.Node.Change.Reboot, nodecfg.ReasonWifi) || len(ck.Diff) == 0 {
		t.Fatalf("check: %d %s", code, b)
	}
	// Its address as a push checks it: DHCP on a no_dhcp network (settings.json) is refused
	// for the node, apart from a rollout's refusals.
	if err := settings.Save(settings.Path(dir), settings.Settings{NoDHCP: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	req, _ = json.Marshal(map[string]string{"text": `{"name":"w","network":{"address":"dhcp"}}`, "node": node.addr})
	code, b = do("POST", "/api/configs/w.json/check", string(req))
	ck = configs.Result{}
	json.Unmarshal([]byte(b), &ck)
	if code != 200 || ck.OK || ck.Node == nil || !strings.Contains(ck.Node.Address, "no DHCP server") || ck.Node.Refusal != "" {
		t.Errorf("check, dhcp on no_dhcp: %d %s", code, b)
	}
	if err := os.Remove(settings.Path(dir)); err != nil {
		t.Fatal(err)
	}
	if code, b := do("POST", "/api/configs/w.json/check", `{"text":"{}","node":"198.51.100.1"}`); code != 400 || !strings.Contains(b, "not a node") {
		t.Errorf("check on an unknown node: %d %s", code, b)
	}
	// Save: the stand-in keeps the saved password; a stale hash is a conflict.
	req, _ = json.Marshal(map[string]string{"text": strings.Replace(got.Text, `"w"`, `"w2"`, 1), "hash": got.Hash})
	if code, b := do("POST", "/api/configs/w.json", string(req)); code != 200 || strings.Contains(b, "hunter2") {
		t.Fatalf("save: %d %s", code, b)
	}
	if b, _ := os.ReadFile(filepath.Join(configs.Path(dir), "w.json")); !strings.Contains(string(b), `"hunter2hunter2"`) || !strings.Contains(string(b), `"w2"`) {
		t.Fatalf("saved %s", b)
	}
	if code, _ := do("POST", "/api/configs/w.json", string(req)); code != 409 {
		t.Errorf("a stale hash: %d", code)
	}
	// A new file with the stand-in and nothing saved: refused; a bad config: refused.
	if code, b := do("POST", "/api/configs/n.json", `{"text":"{\"wifi\":{\"ssid\":\"x\",\"password\":\"`+configs.Hidden+`\"}}","hash":""}`); code != 400 || !strings.Contains(b, "hidden") {
		t.Errorf("new with the stand-in: %d %s", code, b)
	}
	if code, b := do("POST", "/api/configs/n.json", `{"text":"{\"fowarders\":[]}","hash":""}`); code != 400 || !strings.Contains(b, "unknown field") {
		t.Errorf("bad: %d %s", code, b)
	}
	if code, _ := do("POST", "/api/configs/n.json", `{"text":"{\"name\":\"n\"}","hash":""}`); code != 200 {
		t.Errorf("new: %d", code)
	}
	es, _ := actionlog.Tail(dir, 0)
	if len(es) != 2 || es[0].Event != "save" || es[0].Who != "admin" || !slices.Equal(es[0].Args, []string{"w.json", "changed: name"}) ||
		!slices.Equal(es[1].Args, []string{"n.json", "new"}) {
		t.Errorf("action log %+v", es)
	}
	for _, en := range es {
		if b, _ := json.Marshal(en); strings.Contains(string(b), "hunter2") {
			t.Errorf("the password in the action log: %s", b)
		}
	}
	if h, _ := configs.History(dir, "w.json"); len(h) != 1 {
		t.Errorf("history %v", h)
	}
	// Not JSON: refused, as the jobs' POSTs.
	r := httptest.NewRequest("POST", "http://127.0.0.1:8480/api/configs/n.json", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	r.AddCookie(&http.Cookie{Name: auth.CookieName(r.Host), Value: cookie})
	r.Header.Set(auth.TokenHeader, tok)
	if w := serve(h, r); w.Code != http.StatusForbidden {
		t.Errorf("text/plain: %d", w.Code)
	}
	// Names that aren't a config in the directory: never read or written outside it.
	os.WriteFile(filepath.Join(dir, "outside.json"), []byte(`{"name":"o"}`), 0o600)
	for _, p := range []string{"..%2Foutside.json", "%2E%2E%2Foutside.json", ".history", ".pushed", "%2Fetc%2Fpasswd",
		"W.json", "w.json%00", strings.Repeat("a", 70) + ".json", "settings.json", "fleet.json"} {
		if code, _ := do("GET", "/api/configs/"+p, ""); code == 200 {
			t.Errorf("GET %s: %d", p, code)
		}
		if code, _ := do("POST", "/api/configs/"+p, `{"text":"{\"name\":\"x\"}","hash":""}`); code == 200 {
			t.Errorf("POST %s: %d", p, code)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "outside.json")); string(b) != `{"name":"o"}` {
		t.Errorf("outside the directory: %s", b)
	}
}

// A push refuses a config's address as espdns config does (internal/configs,
// AddressRefusal): DHCP on a network in settings.json's no_dhcp, and a move onto an address
// another host answers on though nothing here lists it (adoption's check, asking it).
func TestConfigPushAddressChecks(t *testing.T) {
	k := newTestKey(t)
	n, peer, other := newCfgNode(t, k), newCfgNode(t, k), newCfgNode(t, k)
	e := newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}, NoDHCP: []string{"127.0.0.0/8"}},
		map[string]string{"d.json": `{"name":"d","network":{"address":"dhcp"}}`}, nil)
	if _, err := e.run(params(n.addr, "d.json", true, "")); err == nil || !strings.Contains(err.Error(), "no DHCP server") {
		t.Errorf("dhcp: %v", err)
	}
	// The new address reaches another node, which no list here names.
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "198.51.100.9:") {
				addr = other.addr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	e = newPushEnv(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}},
		map[string]string{"m.json": `{"name":"m","network":{"address":"198.51.100.9/24","gateway":"198.51.100.1"}}`}, hc)
	j, err := e.run(params(n.addr, "m.json", true, ""))
	if err != nil || j.State != jobs.Failed || !strings.Contains(j.Error, "isn't free: 198.51.100.9 is in use by node "+other.id()) {
		t.Errorf("taken: %v %+v", err, j)
	}
	for _, x := range []*cfgNode{n, peer, other} {
		if len(x.took()) != 0 {
			t.Errorf("%s took %v", x.addr, x.took())
		}
	}
}

// A config that would move its node onto another node's address (the wrong node's config
// picked) is refused before anything is touched, dry run or push.
func TestConfigPushMoveOntoTaken(t *testing.T) {
	k := newTestKey(t)
	n, peer := newCfgNode(t, k), newCfgNode(t, k)
	for _, s := range []settings.Settings{
		{Nodes: []string{n.addr, peer.addr, "192.0.2.9"}},
		{Nodes: []string{n.addr, peer.addr}, DNSPeers: []string{"192.0.2.9"}},
	} {
		e := newPushEnv(t, k, s,
			map[string]string{"m.json": `{"name":"m","network":{"address":"192.0.2.9/23","gateway":"192.0.2.1"}}`}, nil)
		_, err := e.run(params(n.addr, "m.json", true, ""))
		if err == nil || !strings.Contains(err.Error(), "which is 192.0.2.9's address") {
			t.Errorf("%+v: %v", s, err)
		}
		if len(n.took()) != 0 {
			t.Errorf("took %v", n.took())
		}
	}
}

// The list names each config's nodes: the node reporting its name; a config written for a
// node's address that reports another name matches no node, and says the node there.
func TestConfigsListMatches(t *testing.T) {
	dir := t.TempDir()
	net := `"network":{"address":"192.0.2.53/24","gateway":"192.0.2.1"}`
	for name, text := range map[string]string{"node-a.json": `{"name":"node-a",` + net + `}`, "stray.json": `{"name":"stray",` + net + `}`} {
		if _, err := configs.Save(dir, name, []byte(text), ""); err != nil {
			t.Fatal(err)
		}
	}
	st := map[string]any{"node_id": "02:00:00:00:00:53", "config": map[string]any{"source": "node", "seq": 1, "name": "node-a",
		"address": "static", "ip": "192.0.2.53/24"}}
	c := configsServer{dataDir: dir, nodes: func() []nodes.Node {
		return []nodes.Node{{Addr: "192.0.2.53", ID: "02:00:00:00:00:53", Online: true, Status: st}}
	}}
	w := httptest.NewRecorder()
	c.list(w, httptest.NewRequest("GET", "/api/configs", nil))
	var out struct {
		Configs []configEntry `json:"configs"`
		Nodes   []configNode  `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Configs) != 2 {
		t.Fatal(err, w.Body.String())
	}
	for _, e := range out.Configs {
		switch e.Name {
		case "node-a.json":
			if len(e.Nodes) != 1 || e.Nodes[0].Host != "192.0.2.53" || len(e.AtAddress) != 0 {
				t.Errorf("node-a.json: %+v", e)
			}
		case "stray.json":
			if len(e.Nodes) != 0 || len(e.AtAddress) != 1 || e.AtAddress[0].Name != "node-a" {
				t.Errorf("stray.json: %+v", e)
			}
		}
	}
	if len(out.Nodes) != 1 || out.Nodes[0].Config == nil || *out.Nodes[0].Config != "node-a.json" {
		t.Errorf("nodes: %+v", out.Nodes)
	}
}
