package fleet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/pins"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// world is a set of fake nodes and what happened to them, in order.
type world struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	pins   *pins.Ledger // each node pinned to its address, as adopted
	mu     sync.Mutex
	nodes  map[string]*fakeNode // by host (127.0.0.1:port)
	events []string             // "host: what"
	down   int                  // nodes down right now
	maxDn  int                  // most nodes down at once
}

func newWorld(t *testing.T) *world {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &world{t: t, key: k, pins: pins.Open(t.TempDir()), nodes: map[string]*fakeNode{}}
}

func (w *world) event(host, what string) {
	w.events = append(w.events, host+": "+what)
}

func (w *world) eventsOf(host string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, e := range w.events {
		if h, what, _ := strings.Cut(e, ": "); h == host {
			out = append(out, what)
		}
	}
	return out
}

// pushes is every release and OTA, in order, as "host kind".
func (w *world) pushes() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, e := range w.events {
		if h, what, _ := strings.Cut(e, ": "); strings.HasPrefix(what, "push ") {
			out = append(out, h+" "+strings.TrimPrefix(what, "push "))
		}
	}
	return out
}

// loopback is an HTTP client that reaches only this host: tests never touch the LAN.
var loopback = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasPrefix(addr, "127.0.0.1:") {
			return nil, errors.New("test: no network beyond loopback")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}}

func (w *world) client() *Client {
	return &Client{Pusher: &release.Pusher{Key: w.key, Pins: w.pins, Client: loopback}, HTTP: loopback, DNS: w, Poll: 2 * time.Millisecond,
		Logf: func(f string, a ...any) { w.t.Logf(f, a...) }}
}

// fakeNode is a node's HTTP side, as firmware/main serves it.
type fakeNode struct {
	w    *world
	host string
	srv  *httptest.Server

	modern       bool // /health, "reboot" in /status, the reboot command and X-OTA-Reboot: later
	id           string
	image        string
	elf          string
	slot         string
	otaState     string
	trialPolls   int // /status polls a new build stays on trial
	bootAt       time.Time
	uptimeBase   int64
	downPolls    int // /status polls left while it reboots
	state        string
	reasons      []string
	seq          map[string]uint64
	blocklist    Stored
	prevList     *Stored // the older copy a revert goes back to
	rebootNeeded bool    // a blocklist doesn't fit next to the old one: it needs a reboot
	pending      []string
	staged       string // firmware elf waiting for the reboot
	rollback     bool   // a new build fails its health check and the node goes back
	afterPush    func() // runs after a release applies (to break the node)
	dnsBroken    bool
	unadopted    bool   // on the defaults, on the address it was flashed with: not in service
	addr         string // the static address it reports ("ip"), with the prefix length; "": none
	blips        int    // /status requests left that fail although the node stays up
	notBlocking  bool
	services     map[string]string // /status "services" (name: state); nil: firmware from before them
	memory       map[string]any    // /status "memory"; nil: firmware from before the memory plan
	blocking     map[string]any    // /status "blocking"
	startPolls   int               // /status polls blocking stays "starting" after a boot (its list loading)
	startLeft    int
	wasStarting  bool // it reported blocking "starting"
	queriedEarly int  // DNS queries it got while a service was starting
}

func (w *world) node(modern bool) *fakeNode {
	n := &fakeNode{w: w, modern: modern, image: "esp32p4-rev1", elf: "0000000000000001", slot: "ota_0", otaState: "valid",
		bootAt: time.Now(), uptimeBase: 1000, state: "healthy", seq: map[string]uint64{"firmware": 1, "config": 1,
			"zones": 1, "blocklist": 1, "overrides": 1, "control": 1}, blocklist: Stored{State: "on", Seq: 1}}
	n.srv = httptest.NewServer(n)
	w.t.Cleanup(n.srv.Close)
	n.host = strings.TrimPrefix(n.srv.URL, "http://")
	n.id = fmt.Sprintf("aa:bb:cc:00:00:%02x", len(w.nodes)+1)
	if _, err := w.pins.Pin(n.id, n.host); err != nil {
		w.t.Fatal(err)
	}
	w.mu.Lock()
	w.nodes[n.host] = n
	w.mu.Unlock()
	return n
}

func (n *fakeNode) uptime() int64 { return n.uptimeBase + int64(time.Since(n.bootAt).Seconds()) }

// reboot takes the node down for a few polls; it comes back on the staged build, unless
// that build rolls back. Called with w.mu held.
func (n *fakeNode) reboot() {
	n.w.event(n.host, "down")
	n.downPolls = 3
	n.pending = nil
	n.w.down++
	n.w.maxDn = max(n.w.maxDn, n.w.down)
}

func (n *fakeNode) up() {
	n.w.down--
	n.w.event(n.host, "up")
	n.bootAt, n.uptimeBase = time.Now(), 0
	if n.startPolls > 0 && n.services != nil {
		n.services["blocking"], n.startLeft = "starting", n.startPolls
	}
	if n.staged != "" {
		if !n.rollback {
			n.elf, n.otaState, n.trialPolls = n.staged, "trial", 2
			n.slot = map[string]string{"ota_0": "ota_1", "ota_1": "ota_0"}[n.slot]
		}
		n.staged = ""
	}
}

func (n *fakeNode) status() map[string]any {
	st := map[string]any{"node_id": n.id, "image": n.image, "board": "p4-ip101", "elf_sha256": n.elf, "slot": n.slot,
		"ota_state": n.otaState, "uptime_s": n.uptime(), "seq": n.seq, "version": "1",
		"keys":   []string{release.Fingerprint(release.PublicRaw(n.w.key)), "0000000000000000"},
		"config": map[string]any{"source": "node", "seq": n.seq["config"], "address": "static"},
		"zones":  []map[string]any{{"name": "home.example"}},
		"hosted": map[string]any{"state": "on", "seq": n.seq["zones"], "limit_bytes": 65536},
	}
	if n.services != nil {
		var svcs []map[string]any
		for name, state := range n.services {
			svcs = append(svcs, map[string]any{"name": name, "state": state, "memory": nil})
		}
		st["services"] = svcs
	}
	if n.memory != nil {
		st["memory"] = n.memory
	}
	if n.blocking != nil {
		st["blocking"] = n.blocking
	}
	if n.unadopted {
		cfg := map[string]any{"source": "defaults", "seq": n.seq["config"], "address": "none", "address_from": "none"}
		if n.addr != "" {
			cfg["address"], cfg["address_from"], cfg["ip"], cfg["gateway"] = "static", "board", n.addr, "192.0.2.1"
		}
		st["config"] = cfg
	}
	if n.modern {
		st["health"] = map[string]any{"state": n.state, "answering": n.answering(), "reasons": n.reasons}
		st["reboot"] = map[string]any{"pending": len(n.pending) > 0, "reasons": n.pending}
	}
	return st
}

func (n *fakeNode) answering() bool { return n.state == "healthy" || n.state == "degraded" }

func (n *fakeNode) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w := n.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if n.downPolls > 0 {
		if r.URL.Path == "/status" {
			if n.downPolls--; n.downPolls == 0 {
				n.up()
			}
		}
		http.Error(rw, "down", http.StatusServiceUnavailable)
		return
	}
	if n.blips > 0 && r.URL.Path == "/status" {
		n.blips--
		http.Error(rw, "busy", http.StatusServiceUnavailable)
		return
	}
	switch r.URL.Path {
	case "/status":
		if n.services["blocking"] == "starting" {
			n.wasStarting = true
			if n.startLeft--; n.startLeft <= 0 {
				n.services["blocking"] = "running"
			}
		}
		if n.otaState == "trial" {
			if n.trialPolls--; n.trialPolls <= 0 {
				n.otaState = "valid"
			}
		}
		json.NewEncoder(rw).Encode(n.status())
	case "/health":
		if !n.modern {
			http.Error(rw, "Nothing matches the given URI", http.StatusNotFound)
			return
		}
		code := http.StatusOK
		if !n.answering() {
			code = http.StatusServiceUnavailable
		}
		rw.WriteHeader(code)
		json.NewEncoder(rw).Encode(map[string]any{"state": n.state, "answering": n.answering(), "reasons": n.reasons,
			"blocklist": n.blocklist, "zones": Stored{State: "on", Seq: n.seq["zones"]}})
	case "/release", "/ota":
		body, _ := io.ReadAll(r.Body)
		if len(body) < release.HeaderLen || !release.Verify(release.PublicRaw(w.key), body) {
			http.Error(rw, "bad signature", http.StatusForbidden)
			return
		}
		kind := release.Kind(body[8])
		seq := binary.LittleEndian.Uint64(body[32:])
		payload := body[release.HeaderLen:]
		if seq <= n.seq[kind.String()] {
			http.Error(rw, "seq not newer", http.StatusForbidden)
			return
		}
		if kind == release.Control && len(payload) == 2 && payload[0] == 5 && (n.prevList == nil || n.prevList.Seq >= n.blocklist.Seq) {
			http.Error(rw, "no previous list to revert to", http.StatusForbidden)
			return
		}
		n.seq[kind.String()] = seq
		later := r.Header.Get("X-OTA-Reboot") == "later"
		w.event(n.host, fmt.Sprintf("push %s", kind))
		reply := n.apply(kind, seq, payload, later)
		if n.afterPush != nil {
			n.afterPush()
		}
		if !n.modern || r.URL.Path == "/ota" && !later {
			fmt.Fprintln(rw, reply)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"ok": true, "message": reply, "reboot_pending": len(n.pending) > 0,
			"rebooting": n.downPolls > 0})
	default:
		http.NotFound(rw, r)
	}
}

// apply is what the node does with a verified release. Called with w.mu held.
func (n *fakeNode) apply(kind release.Kind, seq uint64, payload []byte, later bool) string {
	switch kind {
	case release.Firmware:
		d, err := release.ParseAppDesc(payload)
		if err != nil {
			return "bad image"
		}
		n.staged = d.ElfSHA256
		if later && n.modern {
			n.pending = append(n.pending, "firmware")
			return "ok, firmware staged"
		}
		n.reboot()
		return "ok, rebooting"
	case release.Control:
		if payload[0] == 4 {
			n.w.event(n.host, fmt.Sprintf("reboot command %x", payload))
			if payload[5]&1 != 0 && len(n.pending) == 0 {
				return "ok, no reboot pending: not rebooting"
			}
			n.reboot()
			return "ok, rebooting"
		}
		if payload[0] == 5 {
			from := n.blocklist
			n.blocklist, n.prevList = *n.prevList, &from
			return fmt.Sprintf("ok, list reverted to seq %d from seq %d", n.blocklist.Seq, from.Seq)
		}
		return "ok"
	case release.Blocklist:
		if n.blocklist.State == "on" {
			old := n.blocklist
			n.prevList = &old
		}
		n.blocklist = Stored{State: "on", Seq: seq}
		if !n.rebootNeeded {
			return fmt.Sprintf("ok, blocklist seq %d applied live", seq)
		}
		if n.modern {
			n.pending = append(n.pending, "blocklist: size")
			return fmt.Sprintf("ok, blocklist seq %d stored; it applies at the next boot", seq)
		}
		n.reboot()
		return fmt.Sprintf("ok, blocklist seq %d stored; rebooting to apply it (two copies don't fit)", seq)
	}
	return fmt.Sprintf("ok, %s seq %d applied live", kind, seq)
}

// Exchange is the nodes' DNS side.
func (w *world) Exchange(_ context.Context, host string, m *dns.Msg) (*dns.Msg, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := w.nodes[host]
	if n == nil || n.downPolls > 0 || !n.answering() {
		return nil, errors.New("timeout")
	}
	for _, st := range n.services {
		if st == "starting" {
			n.queriedEarly++
		}
	}
	r := new(dns.Msg)
	r.SetReply(m)
	q := m.Question[0]
	switch {
	case n.dnsBroken:
		r.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeSOA:
		r.Authoritative = true
		rr, _ := dns.NewRR(q.Name + " 60 IN SOA ns. host. 1 60 60 60 60")
		r.Answer = append(r.Answer, rr)
	case n.services["forwarding"] == "off":
		r.Rcode = dns.RcodeRefused // not its own zone (the SOA above), and forwarding off
	case strings.HasSuffix(q.Name, ".invalid."):
		r.Rcode = dns.RcodeNameError
	case q.Name == "ads.example." && !n.notBlocking:
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A: net.IPv4zero})
	default:
		r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A: net.IPv4(192, 0, 2, 1)})
	}
	return r, nil
}

// app is a firmware image whose app descriptor names elf (8 bytes, hex).
func app(t *testing.T, elf string) []byte {
	b := make([]byte, 1024)
	b[0] = 0xE9
	binary.LittleEndian.PutUint32(b[32:], 0xABCD5432)
	copy(b[32+16:], "v2")
	copy(b[32+48:], "dns2")
	e, err := hex.DecodeString(elf)
	if err != nil || len(e) != 8 {
		t.Fatal("bad elf")
	}
	copy(b[32+144:], e)
	return b
}
