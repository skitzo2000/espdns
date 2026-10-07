package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/fakenode"
	"github.com/skitzo2000/espdns/controller/internal/fleet"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
	"github.com/skitzo2000/espdns/controller/internal/zones"
)

// ctlNode is a fake node that takes control releases as the firmware does: signed by the
// release key in slot 0, for its node ID and chip image, with a seq above its last. It
// records each command it took; a reboot takes it down for a moment.
type ctlNode struct {
	t       *testing.T
	pub     []byte
	addr    string
	mu      sync.Mutex
	pending bool
	healthy bool
	down    bool
	boot    time.Time
	seq     uint64
	got     []string
}

func newCtlNode(t *testing.T, key *ecdsa.PrivateKey, pending bool) *ctlNode {
	n := &ctlNode{t: t, pub: release.PublicRaw(key), pending: pending, healthy: true, boot: time.Now().Add(-time.Hour)}
	srv := httptest.NewServer(http.HandlerFunc(n.serve))
	t.Cleanup(srv.Close)
	n.addr = strings.TrimPrefix(srv.URL, "http://")
	return n
}

func (n *ctlNode) commands() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.got)
}

func (n *ctlNode) serve(w http.ResponseWriter, r *http.Request) {
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
		json.NewEncoder(w).Encode(map[string]any{"node_id": "30:ed:a0:00:00:01", "image": "esp32p4-rev1", "board": "p4-ip101",
			"keys":     []string{release.Fingerprint(n.pub), "0000000000000000"},
			"seq":      map[string]uint64{"control": n.seq, "config": 1},
			"uptime_s": int64(time.Since(n.boot).Seconds()),
			"config":   map[string]any{"source": "node", "seq": 1, "address": "static"},
			"health":   map[string]any{"state": state, "answering": n.healthy, "reasons": []string{}},
			"reboot":   map[string]any{"pending": n.pending, "reasons": []string{"config: address"}}})
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

// release checks a release as the firmware does and applies a control command.
func (n *ctlNode) release(b []byte) (map[string]any, error) {
	if len(b) < release.HeaderLen || !release.Verify(n.pub, b[:release.HeaderLen]) {
		return nil, fmt.Errorf("bad signature")
	}
	m, payload := b[:release.ManifestLen], b[release.HeaderLen:]
	seq := binary.LittleEndian.Uint64(m[32:])
	sum := sha256.Sum256(payload)
	switch {
	case release.Kind(m[8]) != release.Control || m[9] != release.KeyRelease:
		return nil, fmt.Errorf("kind %d key %d", m[8], m[9])
	case string(m[10:16]) != "\x30\xed\xa0\x00\x00\x01" || strings.TrimRight(string(m[16:32]), "\x00") != "esp32p4-rev1":
		return nil, fmt.Errorf("not for this node")
	case seq <= n.seq:
		return nil, fmt.Errorf("seq %d not above %d", seq, n.seq)
	case binary.LittleEndian.Uint64(m[40:]) != uint64(len(payload)) || string(sum[:]) != string(m[48:80]):
		return nil, fmt.Errorf("payload hash")
	}
	n.seq = seq
	switch payload[0] {
	case 2:
		n.got = append(n.got, fmt.Sprintf("identify %d", binary.LittleEndian.Uint32(payload[1:])))
		return map[string]any{"ok": true, "message": "identifying"}, nil
	case 3:
		n.got = append(n.got, "flush")
		return map[string]any{"ok": true, "message": "cache flushed"}, nil
	case 4:
		if payload[5] == 1 && !n.pending {
			n.got = append(n.got, "reboot refused: none pending")
			return map[string]any{"ok": true, "message": "no reboot pending"}, nil
		}
		n.got = append(n.got, "reboot")
		n.down = true
		go func() {
			time.Sleep(200 * time.Millisecond)
			n.mu.Lock()
			n.down, n.pending, n.boot = false, false, time.Now()
			n.mu.Unlock()
		}()
		return map[string]any{"ok": true, "message": "rebooting", "rebooting": true}, nil
	}
	return nil, fmt.Errorf("unknown command %d", payload[0])
}

type keyOf struct{ k *ecdsa.PrivateKey }

func (s keyOf) Key() (*ecdsa.PrivateKey, error) {
	if s.k == nil {
		return nil, fmt.Errorf("%w: test", keys.ErrNoKey)
	}
	return s.k, nil
}
func (keyOf) String() string { return "test key" }

// runAction runs one action job against the nodes in s, and returns the job (or the
// refusal to queue it).
func runAction(t *testing.T, key *ecdsa.PrivateKey, s settings.Settings, kind, params string) (jobs.Job, error) {
	return runActionIn(t, t.TempDir(), true, key, s, kind, params)
}

// runActionIn is runAction in dir, the node pinned there first (as adopting it) only with pin.
func runActionIn(t *testing.T, dir string, pin bool, key *ecdsa.PrivateKey, s settings.Settings, kind,
	params string) (jobs.Job, error) {
	if err := settings.Save(settings.Path(dir), s); err != nil {
		t.Fatal(err)
	}
	var target struct {
		Node string `json:"node"`
	}
	if json.Unmarshal([]byte(params), &target) == nil && target.Node != "" && pin {
		pinAt(t, dir, target.Node)
	}
	a := answers{asked: make(chan string, 100)}
	act := actions{dataDir: dir, key: keyOf{key}, known: func() []string { return s.Nodes },
		client: func() *fleet.Client { return &fleet.Client{DNS: a, PeerDNS: a, Poll: 20 * time.Millisecond} }}
	r := jobs.New(dir, act.kinds())
	r.Logf = t.Logf
	runJobs(t, r)
	j, err := r.Start(kind, "admin", json.RawMessage(params))
	if err != nil {
		return j, err
	}
	for range 1000 {
		if j, _ = r.Get(j.ID); j.State.Ended() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	es, _ := actionlog.Tail(dir, 0)
	if len(es) > 2 && !pin { // dir shared by runs: this one's two
		es = es[len(es)-2:]
	}
	if len(es) != 2 || es[0].Action != "job "+kind || es[0].Who != "admin" || es[0].Source != "controller" ||
		len(es[0].Args) != 1 || !strings.Contains(es[0].Args[0], `"node"`) {
		t.Fatalf("action log %+v", es)
	}
	return j, nil
}

// pinAt pins the node answering at host to it in dataDir, as adopting it would have
// (internal/pins); nothing for a host that doesn't answer.
func pinAt(t *testing.T, dataDir, host string) {
	t.Helper()
	st, err := (&fleet.Client{}).Status(context.Background(), host)
	if err != nil {
		return
	}
	if _, err := pins.Open(dataDir).Pin(st.NodeID, host); err != nil {
		t.Fatal(err)
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIdentifyAndFlush(t *testing.T) {
	k := newTestKey(t)
	n := newCtlNode(t, k, false)
	s := settings.Settings{Nodes: []string{n.addr}}
	j, err := runAction(t, k, s, "identify", `{"node":"`+n.addr+`","seconds":45}`)
	if err != nil || j.State != jobs.Done {
		t.Fatalf("identify: %+v %v", j, err)
	}
	j, err = runAction(t, k, s, "identify", `{"node":"`+n.addr+`"}`)
	if err != nil || j.State != jobs.Done {
		t.Fatalf("identify, default: %+v %v", j, err)
	}
	j, err = runAction(t, k, s, "flush", `{"node":"`+n.addr+`"}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "cache flushed") {
		t.Fatalf("flush: %+v %v", j, err)
	}
	if got := strings.Join(n.commands(), ", "); got != "identify 45, identify 30, flush" {
		t.Fatalf("the node took: %s", got)
	}

	// A node not adopted yet (pinned nowhere): identify is signed for the ID its /status
	// gives, as the Adopt page asks (its seq recorded); every other action is refused.
	dir := t.TempDir()
	j, err = runActionIn(t, dir, false, k, s, "identify", `{"node":"`+n.addr+`","seconds":5}`)
	if err != nil || j.State != jobs.Done {
		t.Fatalf("identify, not adopted: %+v %v", j, err)
	}
	if seq, err := pins.Open(dir).Seq("30:ed:a0:00:00:01", "control"); err != nil || seq == 0 {
		t.Fatalf("its control seq recorded: %d %v", seq, err)
	}
	if _, err := pins.Open(dir).Pinned(n.addr); !errors.Is(err, pins.ErrNotPinned) {
		t.Fatalf("identify pinned it: %v", err)
	}
	j, err = runActionIn(t, dir, false, k, s, "flush", `{"node":"`+n.addr+`"}`)
	if err != nil || j.State != jobs.Failed || !strings.Contains(j.Error, "not pinned") {
		t.Fatalf("flush, not adopted: %+v %v", j, err)
	}
	// ... and an ID pinned to another address gets nothing signed here.
	if _, err := pins.Open(dir).Pin("30:ed:a0:00:00:01", "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	j, err = runActionIn(t, dir, false, k, s, "identify", `{"node":"`+n.addr+`"}`)
	if err != nil || j.State != jobs.Failed || !strings.Contains(j.Error, "pinned to 192.0.2.77") {
		t.Fatalf("identify, pinned elsewhere: %+v %v", j, err)
	}
	if got := strings.Join(n.commands(), ", "); got != "identify 45, identify 30, flush, identify 5" {
		t.Fatalf("the node took: %s", got)
	}

	// Refused before they are queued: no key, a node the controller doesn't know, bad params.
	for _, c := range []struct {
		key          *ecdsa.PrivateKey
		kind, params string
		want         string
	}{
		{nil, "flush", `{"node":"` + n.addr + `"}`, "no release key"},
		{k, "identify", `{"node":"192.0.2.9"}`, "not a node the controller knows"},
		{k, "flush", `{"node":"192.0.2.9"}`, "not in settings.json"},
		{k, "identify", `{"node":"` + n.addr + `","seconds":0}`, "1 to 3600"},
		{k, "identify", `{"node":"` + n.addr + `","seconds":3601}`, "1 to 3600"},
		{k, "flush", `{"node":"` + n.addr + `","seconds":5}`, "only for identify and pause"},
		{k, "flush", `{"node":"` + n.addr + `","x":1}`, "unknown field"},
		{k, "flush", `{}`, "need \"node\""},
	} {
		if _, err := runAction(t, c.key, s, c.kind, c.params); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, want %q", c.kind, c.params, err, c.want)
		}
	}
	// A key the node doesn't trust: the job fails, the node takes nothing.
	j, _ = runAction(t, newTestKey(t), s, "flush", `{"node":"`+n.addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "not the one") {
		t.Fatalf("untrusted key: %+v", j)
	}
	if len(n.commands()) != 4 {
		t.Fatal(n.commands())
	}
}

func TestRebootPending(t *testing.T) {
	k := newTestKey(t)
	// The pending node and a healthy peer: rebooted, waited for, back in service.
	n, peer := newCtlNode(t, k, true), newCtlNode(t, k, false)
	j, err := runAction(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, "reboot-pending", `{"node":"`+n.addr+`"}`)
	if err != nil || j.State != jobs.Done {
		t.Fatalf("%+v %v", j, err)
	}
	if got := n.commands(); len(got) != 1 || got[0] != "reboot" || len(peer.commands()) != 0 {
		t.Fatalf("node %v, peer %v", got, peer.commands())
	}
	logText := ""
	for _, l := range j.Log {
		logText += l.Text + "\n"
	}
	if !strings.Contains(logText, "back after") || !strings.Contains(logText, "back in service") {
		t.Fatalf("log:\n%s", logText)
	}

	// Nothing pending now: refused, no reboot sent.
	j, _ = runAction(t, k, settings.Settings{Nodes: []string{n.addr, peer.addr}}, "reboot-pending", `{"node":"`+n.addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "no reboot pending") || len(n.commands()) != 1 {
		t.Fatalf("not pending: %+v %v", j, n.commands())
	}

	// The only node: never the last one answering.
	only := newCtlNode(t, k, true)
	j, _ = runAction(t, k, settings.Settings{Nodes: []string{only.addr}}, "reboot-pending", `{"node":"`+only.addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "only node") || len(only.commands()) != 0 {
		t.Fatalf("the only node: %+v %v", j, only.commands())
	}

	// The other node not answering: this one is the last healthy node.
	sick := newCtlNode(t, k, false)
	sick.mu.Lock()
	sick.healthy = false
	sick.mu.Unlock()
	last := newCtlNode(t, k, true)
	j, _ = runAction(t, k, settings.Settings{Nodes: []string{last.addr, sick.addr}}, "reboot-pending", `{"node":"`+last.addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "last healthy node") || len(last.commands()) != 0 {
		t.Fatalf("the last healthy node: %+v %v", j, last.commands())
	}

	// A DNS peer answering counts as the other one.
	alone := newCtlNode(t, k, true)
	j, _ = runAction(t, k, settings.Settings{Nodes: []string{alone.addr}, DNSPeers: []string{"198.51.100.254"}}, "reboot-pending", `{"node":"`+alone.addr+`"}`)
	if j.State != jobs.Done || len(alone.commands()) != 1 {
		t.Fatalf("with a DNS peer: %+v %v", j, alone.commands())
	}
	// One not answering doesn't.
	alone2 := newCtlNode(t, k, true)
	j, _ = runAction(t, k, settings.Settings{Nodes: []string{alone2.addr}, DNSPeers: []string{"203.0.113.9"}}, "reboot-pending", `{"node":"`+alone2.addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "last healthy node") || len(alone2.commands()) != 0 {
		t.Fatalf("with a DNS peer not answering: %+v %v", j, alone2.commands())
	}
}

// A node found only over mDNS (any host can advertise one, and have a release signed for
// another node's ID): identify, yes; flush and reboot-pending, only for settings.json's.
func TestActionsOnlyListedChange(t *testing.T) {
	k := newTestKey(t)
	dir := t.TempDir()
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{"198.51.100.1"}}); err != nil {
		t.Fatal(err)
	}
	act := actions{dataDir: dir, key: keyOf{k}, known: func() []string { return []string{"198.51.100.1", "198.51.100.66"} }}
	if _, err := act.identify(json.RawMessage(`{"node":"198.51.100.66"}`)); err != nil {
		t.Errorf("identify an mDNS node: %v", err)
	}
	for _, kind := range []string{"flush", "revert", "reboot-pending"} {
		if _, err := act.kinds()[kind](json.RawMessage(`{"node":"198.51.100.66"}`)); err == nil || !strings.Contains(err.Error(), "not in settings.json") {
			t.Errorf("%s an mDNS node: %v", kind, err)
		}
		if _, err := act.kinds()[kind](json.RawMessage(`{"node":"198.51.100.1"}`)); err != nil {
			t.Errorf("%s a listed node: %v", kind, err)
		}
	}
}

// swapKey is a key source whose key can go away.
type swapKey struct{ k **ecdsa.PrivateKey }

func (s swapKey) Key() (*ecdsa.PrivateKey, error) {
	if *s.k == nil {
		return nil, fmt.Errorf("%w: test", keys.ErrNoKey)
	}
	return *s.k, nil
}
func (swapKey) String() string { return "swap" }

// The key is read again when the job runs: one removed while the job waited isn't used.
func TestActionKeyReadAtRun(t *testing.T) {
	k := newTestKey(t)
	n := newCtlNode(t, k, false)
	dir := t.TempDir()
	settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{n.addr}})
	cur := k
	act := actions{dataDir: dir, key: swapKey{&cur}, known: func() []string { return []string{n.addr} }}
	for _, kind := range []string{"identify", "flush", "revert", "reboot-pending"} {
		cur = k
		fn, err := act.kinds()[kind](json.RawMessage(`{"node":"` + n.addr + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		cur = nil
		if _, err := fn(context.Background(), &jobs.Run{}); err == nil || !strings.Contains(err.Error(), "no release key") {
			t.Errorf("%s: %v", kind, err)
		}
	}
	if len(n.commands()) != 0 {
		t.Fatalf("the node took %v", n.commands())
	}
}

// The hosted zones' revert against a fake node (internal/fakenode, which keeps the two
// slots as hosted.c does): refused while it holds no older bundle, done after a push, then
// refused again (the bundle left is the one reverted from); a push after it ends it;
// /status says the seq, slot and reverted_from.
func TestRevertZones(t *testing.T) {
	k := newTestKey(t)
	fn := fakenode.New("rz", [6]byte{0x02, 0, 0, 0, 0x8, 2}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(k))
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	fn.Addr = strings.TrimPrefix(srv.URL, "http://")
	s := settings.Settings{Nodes: []string{fn.Addr}}
	hosted := func() release.HostedStatus {
		t.Helper()
		st, err := (&fleet.Client{}).Status(context.Background(), fn.Addr)
		if err != nil || st.Hosted == nil || st.Hosted.Slot == nil {
			t.Fatalf("status: %+v %v", st, err)
		}
		return *st.Hosted
	}
	zone, err := zones.ParseMaster("home.example.", strings.NewReader(zoneText), "home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (&zones.Set{Zones: []*zones.Zone{zone}}).Bundle(64)
	if err != nil {
		t.Fatal(err)
	}
	own := t.TempDir()
	pinAt(t, own, fn.Addr)
	p := &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(own)}
	push := func() release.HostedStatus {
		t.Helper()
		if _, err := p.Push(context.Background(), fn.Addr, release.Zones, bundle); err != nil {
			t.Fatal(err)
		}
		return hosted()
	}

	// Only the bundle it came with (seq 1, slot 0): nothing older.
	j, err := runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"zones"}`)
	if err != nil || j.State != jobs.Failed || !strings.Contains(j.Error, "no previous zones to revert to: slot 1 is empty") {
		t.Fatalf("nothing older: %+v %v", j, err)
	}
	pushed := push()
	if *pushed.Slot != 1 || pushed.Seq <= 1 || len(pushed.Zones) != 1 {
		t.Fatalf("pushed: %+v", pushed)
	}
	j, err = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"zones"}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "zones reverted to seq 1 (slot 0)") {
		t.Fatalf("revert: %+v %v", j, err)
	}
	if h := hosted(); h.Seq != 1 || *h.Slot != 0 || h.RevertedFrom != pushed.Seq || len(h.Zones) != 0 {
		t.Fatalf("after the revert: %+v", h)
	}
	j, _ = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"zones"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "not older than seq 1 in use (reverted from)") {
		t.Fatalf("again: %+v", j)
	}
	// A push ends the revert: into the slot not in use, the older copy the one reverted to.
	again := push()
	if *again.Slot != 1 || again.RevertedFrom != 0 || again.Seq <= pushed.Seq {
		t.Fatalf("pushed after the revert: %+v", again)
	}
	j, err = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"zones"}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "zones reverted to seq 1 (slot 0)") {
		t.Fatalf("revert after a push: %+v %v", j, err)
	}
	// Hosted zones off in its config: refused, as the node says.
	fn.Off = []string{"hosted"}
	j, _ = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"zones"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "hosted zones are off") {
		t.Fatalf("off: %+v", j)
	}
	for _, list := range []string{"config", "firmware", "control"} {
		if _, err := runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"`+list+`"}`); err == nil ||
			!strings.Contains(err.Error(), `"blocklist", "overrides" or "zones"`) {
			t.Errorf("revert %s: %v", list, err)
		}
	}
}

// Revert against a fake node (internal/fakenode, which keeps the two slots as the firmware
// does): refused while it holds no older list, done after a second push, then refused
// again (the copy left is the one reverted from); /status says which seq and slot it runs.
func TestRevert(t *testing.T) {
	k := newTestKey(t)
	fn := fakenode.New("rv", [6]byte{0x02, 0, 0, 0, 0x8, 1}, "esp32p4-rev1", "p4-ip101", release.PublicRaw(k))
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	fn.Addr = strings.TrimPrefix(srv.URL, "http://")
	s := settings.Settings{Nodes: []string{fn.Addr}}
	list := func() release.ListStatus {
		t.Helper()
		st, err := (&fleet.Client{}).Status(context.Background(), fn.Addr)
		if err != nil || st.Blocking == nil || st.Blocking.List.Slot == nil {
			t.Fatalf("status: %+v %v", st, err)
		}
		return st.Blocking.List
	}

	// Only the list it came with (seq 1, slot 0): nothing older.
	j, err := runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`"}`)
	if err != nil || j.State != jobs.Failed || !strings.Contains(j.Error, "no previous list to revert to") {
		t.Fatalf("nothing older: %+v %v", j, err)
	}
	own := t.TempDir()
	pinAt(t, own, fn.Addr)
	p := &release.Pusher{Key: k, KeyID: release.KeyRelease, Pins: pins.Open(own)}
	if _, err := p.Push(context.Background(), fn.Addr, release.Blocklist, listFile(t, "doubleclick.net")); err != nil {
		t.Fatal(err)
	}
	pushed := list()
	if *pushed.Slot != 1 || pushed.Seq <= 1 {
		t.Fatalf("pushed: %+v", pushed)
	}
	j, err = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"blocklist"}`)
	if err != nil || j.State != jobs.Done || !strings.Contains(string(j.Result), "reverted to seq 1 (slot 0)") {
		t.Fatalf("revert: %+v %v", j, err)
	}
	if l := list(); l.Seq != 1 || *l.Slot != 0 || l.RevertedFrom != pushed.Seq {
		t.Fatalf("after the revert: %+v", l)
	}
	j, _ = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "not older than seq 1 in use") {
		t.Fatalf("again: %+v", j)
	}
	// The overrides: none in use.
	j, _ = runAction(t, k, s, "revert", `{"node":"`+fn.Addr+`","list":"overrides"}`)
	if j.State != jobs.Failed || !strings.Contains(j.Error, "no overrides in use") {
		t.Fatalf("overrides: %+v", j)
	}
	// Refused before they are queued: what isn't a list, and "list" on another kind.
	for _, c := range []struct{ kind, params, want string }{
		{"revert", `{"node":"` + fn.Addr + `","list":"nonsense"}`, `not "nonsense"`},
		{"flush", `{"node":"` + fn.Addr + `","list":"blocklist"}`, "only for revert"},
		{"revert", `{"node":"192.0.2.9"}`, "not in settings.json"},
	} {
		if _, err := runAction(t, k, s, c.kind, c.params); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, want %q", c.kind, c.params, err, c.want)
		}
	}
}
