package release

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/pins"
)

// NodeStatus is the part of a node's /status a push, a rolling change or a status line
// needs. Fields a node's firmware is too old to send stay at their zero value.
type NodeStatus struct {
	NodeID    string            `json:"node_id"`
	Image     string            `json:"image"`
	Board     string            `json:"board"`
	Keys      []string          `json:"keys"`
	Seq       map[string]uint64 `json:"seq"`
	Project   string            `json:"project"`
	Version   string            `json:"version"`
	Built     string            `json:"built"`
	ElfSHA256 string            `json:"elf_sha256"` // first 8 bytes, hex, as AppDesc.ElfSHA256
	Slot      string            `json:"slot"`
	OTAState  string            `json:"ota_state"` // "trial" until a new firmware confirms itself, then "valid"
	UptimeS   int64             `json:"uptime_s"`
	IP        string            `json:"ip"`
	BootMS    int               `json:"boot_ms"`
	Degraded  bool              `json:"degraded"`
	// BoardSource is where its board definition came from: "partition" (written when it was
	// flashed), "fallback" (built into a transitional image) or "none"; empty on firmware
	// from before board definitions.
	BoardSource string `json:"board_source"`
	// Health is the node's state (firmware/main/health.h); nil on firmware from before it.
	Health *HealthState `json:"health"`
	// Reboot is set by firmware that waits for the controller to reboot it after a release
	// that needs one; nil on firmware that reboots by itself.
	Reboot *RebootStatus `json:"reboot"`
	// Zones are the node's secondary zones: each one's serial and records as copied (0
	// before its first copy).
	Zones []struct {
		Name    string `json:"name"`
		Serial  uint32 `json:"serial"`
		Records int    `json:"records"`
		Expired bool   `json:"expired"`
	} `json:"zones"`
	// ForwardZones are the node's forward zones (conditional forwarders) as it runs them (its
	// config's as of its last boot), each {"name", "forwarder"}.
	ForwardZones ForwardZoneList `json:"forward_zones"`
	// Config is the node's settings source (firmware/main/settings.h); nil on firmware
	// from before node configs.
	Config *ConfigStatus `json:"config"`
	// Hosted is the node's hosted zones (firmware/main/hosted.h); nil on firmware from
	// before them.
	Hosted *HostedStatus `json:"hosted"`
	// Services are the node's services and their states (firmware/main/svc.h); nil on
	// firmware from before them, which runs every service it has.
	Services []ServiceStatus `json:"services"`
	// Memory is the node's memory plan (firmware memplan.h); nil on firmware from before it.
	Memory *MemoryStatus `json:"memory"`
	// Blocking is the lists the node holds (firmware/main/blocking.c); nil on firmware from
	// before blocking.
	Blocking *BlockingStatus `json:"blocking"`
	// QueryLog is the node's query log (firmware querylog.h); nil on firmware from before
	// it, which has no /metrics or /querylog and takes no "querylog" in a config.
	QueryLog *QueryLogStatus `json:"querylog"`
	// CPU is the node's clock scaling (firmware power.h, cpuplan.h); nil on firmware from
	// before it, which takes no "cpu" in a config.
	CPU *CPUStatus `json:"cpu"`
	// Queries are the node's DNS counters since its boot (firmware/main/ota.c); nil if it
	// doesn't report them.
	Queries *QueryCounts `json:"queries"`
	Net     struct {
		Kind     string `json:"kind"` // "ethernet" or "wifi"
		MAC      string `json:"mac"`  // the interface's MAC: what a DHCP reservation names
		Link     bool   `json:"link"`
		Hostname string `json:"hostname"`
	} `json:"net"`
}

// MAC is a MAC address as a node reports it (/status net.mac), checked: six lower-case hex
// pairs with colons ("aa:bb:cc:dd:ee:ff", whatever case it came in), or "" for anything
// else (none reported, all zero: the interface wasn't up, or not a MAC), so a page never
// shows, nor copies, what isn't one.
func MAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 || len(s) != 17 || s[2] != ':' {
		return ""
	}
	if string(hw) == "\x00\x00\x00\x00\x00\x00" {
		return ""
	}
	return hw.String()
}

// CPUStatus is /status's "cpu": clock scaling, and how long the node held its full clock
// for queries (dns) and for background work (work: loads, transfers, releases).
type CPUStatus struct {
	PM      bool   `json:"pm"`   // built with power management
	DFS     bool   `json:"dfs"`  // scaling on
	From    string `json:"from"` // where that comes from: "config", "board", "image" ("boot" until it starts)
	MaxMHz  int    `json:"max_mhz"`
	MinMHz  int    `json:"min_mhz"`
	IdleMHz int    `json:"idle_mhz"` // what it idles at: min_mhz, or the APB floor while the EMAC or Wi-Fi holds it
	Error   string `json:"error"`
	DNS     struct {
		Holds  uint64 `json:"holds"`
		BusyMS uint64 `json:"busy_ms"`
	} `json:"dns"`
	Work struct {
		Holds  uint64 `json:"holds"`
		BusyMS uint64 `json:"busy_ms"`
	} `json:"work"`
}

// HealthState is /status's "health" (and the start of /health).
type HealthState struct {
	State     string   `json:"state"` // booting, healthy, degraded, no network, fault, updating
	Answering bool     `json:"answering"`
	Reasons   []string `json:"reasons"`
}

// RebootStatus is /status's "reboot": whether a release the node took waits for a reboot.
type RebootStatus struct {
	Pending bool     `json:"pending"`
	Reasons []string `json:"reasons"` // what waits: "firmware", "config", "blocklist", ...
	SinceS  int64    `json:"since_s"`
}

// ConfigStatus is /status's "config": where the node's settings come from.
type ConfigStatus struct {
	Source  string `json:"source"` // "node" (a pushed config) or "defaults"
	Seq     uint64 `json:"seq"`
	Storage string `json:"storage"` // "partition", or "nvs" on a node flashed before the config partition
	Trial   bool   `json:"trial"`   // a new address waits to be reached, else the node goes back
	Address string `json:"address"` // "static", "dhcp" (a config asked for it) or "none"
	// AddressFrom is the layer the address came from: "config", "board" (written when the
	// node was flashed), "firmware" (built in) or "none"; empty on firmware from before it.
	AddressFrom string `json:"address_from"`
	IP          string `json:"ip"`      // the static address with its prefix length ("192.0.2.52/24")
	Gateway     string `json:"gateway"` // with a static address
	Name        string `json:"name"`
	Error       string `json:"error"`
}

// ServiceStatus is one of /status's "services".
type ServiceStatus struct {
	Name  string `json:"name"`  // dns, forwarding, forward_zones, secondary, hosted, blocking
	State string `json:"state"` // off, starting, running, failed
	// Memory is its share of the memory plan and what it holds, bytes; nil on firmware from
	// before the plan.
	Memory *struct {
		Planned   int64 `json:"planned"`
		Allocated int64 `json:"allocated"`
	} `json:"memory"`
}

// MemoryStatus is /status's "memory": the board's values the node plans with, and the plan
// per pool (bytes).
type MemoryStatus struct {
	Board    memplan.Board `json:"board"`
	Internal struct {
		Capacity int64 `json:"capacity"`
		Planned  int64 `json:"planned"`
	} `json:"internal"`
	PSRAM struct {
		Capacity int64 `json:"capacity"`
		Planned  int64 `json:"planned"`
	} `json:"psram"`
}

// QueryCounts is /status's "queries": what the node answered since its boot.
type QueryCounts struct {
	Total     uint64 `json:"total"`
	Forwarded uint64 `json:"forwarded"`
	NXDomain  uint64 `json:"nxdomain"`
	Servfail  uint64 `json:"servfail"`
	Refused   uint64 `json:"refused"`
	Dropped   uint64 `json:"dropped"`
}

// List is the blocklist or overrides (k) the node reports, nil when it reports none (no
// "blocking", or another kind).
func (s NodeStatus) List(k Kind) *ListStatus {
	if s.Blocking == nil {
		return nil
	}
	switch k {
	case Blocklist:
		return &s.Blocking.List
	case Overrides:
		return &s.Blocking.Overrides
	}
	return nil
}

// BlockingStatus is /status's "blocking": the main list and the overrides.
type BlockingStatus struct {
	List      ListStatus `json:"list"`
	Overrides ListStatus `json:"overrides"`
	// PausedS is how long blocking stays paused (espdns pause), 0 when it isn't.
	PausedS uint32 `json:"paused_s"`
}

// ForwardZoneStatus is one of /status's "forward_zones".
type ForwardZoneStatus struct {
	Name      string `json:"name"`
	Forwarder string `json:"forwarder"`
}

// ForwardZoneList is /status's "forward_zones", each {"name", "forwarder"}.
type ForwardZoneList []ForwardZoneStatus

// Names are the zones' names.
func (l ForwardZoneList) Names() []string {
	if l == nil {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, z := range l {
		out = append(out, z.Name)
	}
	return out
}

// ListStatus is one list the node holds, as it is loaded.
type ListStatus struct {
	State string `json:"state"` // off, loading, on, failed
	Seq   uint64 `json:"seq"`
	// SHA256 is the payload's (the list file's), hex.
	SHA256  string `json:"sha256,omitempty"`
	Entries uint32 `json:"entries"`
	Tier    string `json:"tier"` // "ram" or "sd" while on
	Bytes   int64  `json:"bytes"`
	// Slot is the SD slot (0 or 1) it was loaded from, -1 while none is; nil on firmware
	// from before it was reported.
	Slot *int `json:"slot,omitempty"`
	// RevertedFrom is the seq a revert command moved it back from (0: none): the node keeps
	// to the older copy until a newer one is pushed.
	RevertedFrom uint64 `json:"reverted_from,omitempty"`
	// Fallback says why the newest copy the node took isn't in use (its slot corrupt,
	// unreadable or too big), when its boot fell back to the older one: health "older copy".
	Fallback string `json:"fallback,omitempty"`
	// DataBytes of Bytes are in the lists' memory (memory.blocklist_kb), InternalBytes (its
	// indexes) in internal RAM (memory.blocklist_index_kb); both nil on firmware from before
	// they were reported.
	DataBytes     *int64 `json:"data_bytes"`
	InternalBytes *int64 `json:"internal_bytes"`
	Error         string `json:"error"`
}

// ServiceOff says whether the node reports the service off in its node config. Firmware
// from before services reports none: every service it has runs.
func (s NodeStatus) ServiceOff(name string) bool {
	for _, v := range s.Services {
		if v.Name == name {
			return v.State == "off"
		}
	}
	return false
}

// Starting is the services the node reports still starting: after a boot or a live
// restart its list and hosted zones load in the background, and each load flushes the DNS
// cache.
func (s NodeStatus) Starting() []string {
	var out []string
	for _, v := range s.Services {
		if v.State == "starting" {
			out = append(out, v.Name)
		}
	}
	return out
}

// HostedStatus is /status's "hosted": the zones bundle in use and the board's limit.
type HostedStatus struct {
	State      string `json:"state"` // off, loading, on, failed
	Seq        uint64 `json:"seq"`
	SHA256     string `json:"sha256"`      // the bundle it runs (its release's payload hash), hex; "" unless on
	Bytes      int    `json:"bytes"`       // what the zones take (zones.Set.Mem)
	LimitBytes int    `json:"limit_bytes"` // the board's memory.hosted_zones_kb, or the firmware default
	// Slot is the SD slot (0 or 1) the bundle in use was loaded from, -1 while none is.
	Slot *int `json:"slot,omitempty"`
	// RevertedFrom is the seq a revert command moved the zones back from (0: none): the
	// node keeps to the older bundle until a newer one is pushed.
	RevertedFrom uint64 `json:"reverted_from,omitempty"`
	// Fallback says why the newest bundle the node took isn't in use, when its boot fell
	// back to the older one (health "older copy"); "" otherwise and on older firmware.
	Fallback string `json:"fallback,omitempty"`
	Error    string `json:"error"`
	Zones    []struct {
		Name    string `json:"name"`
		Serial  uint32 `json:"serial"`
		Records int    `json:"records"`
	} `json:"zones"`
}

// Pusher signs releases for one node and sends them to it.
type Pusher struct {
	Key   *ecdsa.PrivateKey
	KeyID uint8 // KeyRelease or KeyRecovery: the slot Key is in on the nodes
	// Pins is the signer's own record of the nodes (internal/pins): a release is signed for
	// the node ID pinned to the address, with a seq above the last one recorded for it, never
	// for the ID or seq a /status gives (anything answering on the address can send one).
	// Nothing is signed without it.
	Pins *pins.Ledger
	// Unadopted also signs for a node at an address with none pinned, by the ID its /status
	// gives, when that ID is pinned to no other address (pins.Unpinned): for identify on a
	// node not adopted yet, which flickers an LED, so a spoofed /status gets nothing worse.
	// Every other release goes to a pinned node only.
	Unadopted bool
	Client    *http.Client
	Now       func() time.Time
}

func (p *Pusher) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 120 * time.Second}
}

// Status reads a node's /status.
func (p *Pusher) Status(ctx context.Context, host string) (NodeStatus, error) {
	var st NodeStatus
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/status", nil)
	if err != nil {
		return st, err
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("%s/status: %s", host, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, fmt.Errorf("%s/status: %w", host, err)
	}
	return st, nil
}

// trusted checks the node trusts p's key in p's slot.
func (p *Pusher) trusted(host string, st NodeStatus) error {
	fp := Fingerprint(PublicRaw(p.Key))
	if len(st.Keys) == 0 {
		return fmt.Errorf("%s runs firmware from before signed releases: update it once with firmware/tools/ota_push.py", host)
	}
	if int(p.KeyID) >= len(st.Keys) || st.Keys[p.KeyID] != fp {
		return fmt.Errorf("the key (fingerprint %s) is not the one %s trusts in slot %d (%v)", fp, host, p.KeyID, st.Keys)
	}
	return nil
}

// target is who a release of kind for the node at host, whose /status is st, is signed for
// and with which seq, recorded as signed: the node ID pinned to host, never st's, and a seq
// above the last one signed for it (NextSeq), never one from st. A /status that answers as
// another node is refused. With Unadopted, an address with no node pinned is signed for
// st's ID if no other address has it pinned.
func (p *Pusher) target(host string, kind Kind, st NodeStatus) ([6]byte, uint64, error) {
	var node [6]byte
	if p.Pins == nil {
		return node, 0, errors.New("no record of the nodes' pinned IDs and seqs to sign with")
	}
	id, err := p.Pins.Pinned(host)
	if errors.Is(err, pins.ErrNotPinned) && p.Unadopted {
		if id, err = p.Pins.Unpinned(st.NodeID); err != nil {
			return node, 0, fmt.Errorf("%s: %w", host, err)
		}
	} else if errors.Is(err, pins.ErrNotPinned) {
		return node, 0, fmt.Errorf("%s is not pinned to a node: releases are signed only for a node adopted here "+
			"(espdns adopt, the Adopt page) or pinned by hand (espdns pin -host %s -node <its ID>)", host, host)
	}
	if err != nil {
		return node, 0, err
	}
	if !strings.EqualFold(st.NodeID, id) {
		return node, 0, fmt.Errorf("%s answers as node %q, but node %s is pinned there: not signed (something else "+
			"answers on its address; if its board was replaced, pin the new one: espdns pin -host %s -node <its ID>)",
			host, st.NodeID, id, host)
	}
	if node, err = ParseMAC(id); err != nil {
		return node, 0, err
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	// Read, picked and recorded as one step: two pushes at once never pick from one last seq.
	seq, err := p.Pins.Next(id, kind.String(), func(last uint64) (uint64, error) {
		s, err := NextSeq(last, now())
		if err != nil {
			return 0, fmt.Errorf("node %s, %s: %w", id, kind, err)
		}
		return s, nil
	})
	if err != nil {
		return node, 0, err
	}
	return node, seq, nil
}

// Push signs payload as a release of kind for the node at host (its node ID pinned to host,
// its next seq from the record, its chip image from its /status) and posts it to /release.
// It returns the node's reply, which says whether the release applied live or with a reboot.
func (p *Pusher) Push(ctx context.Context, host string, kind Kind, payload []byte) (string, error) {
	r, err := p.PushRelease(ctx, host, kind, payload)
	return r.Reply, err
}

// Pushed is what a push did: the seq it was signed with, the node's /status before it,
// and the node's reply (Reply as a line to show, Node as the node sent it).
type Pushed struct {
	Seq    uint64
	Before NodeStatus
	Reply  string
	Node   Reply
}

// Reply is a node's answer to a release it took: JSON, {"ok","message","reboot_pending",
// "rebooting"}, or a line of text from firmware before that.
type Reply struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// RebootPending: something the node took (this release or an earlier one) applies at
	// its next boot, which waits for the controller (/status "reboot").
	RebootPending bool `json:"reboot_pending"`
	// Rebooting: the node reboots by itself now.
	Rebooting bool `json:"rebooting"`
	// JSON: the node replied in JSON. Firmware from before reboots by itself whenever a
	// release needs it, saying "rebooting".
	JSON bool `json:"-"`
}

// ParseReply reads a node's success reply.
func ParseReply(body string) Reply {
	var r Reply
	if json.Unmarshal([]byte(body), &r) == nil && r.OK {
		r.JSON = true
		return r
	}
	return Reply{OK: true, Message: body, Rebooting: strings.Contains(body, "rebooting")}
}

// line is the reply to show.
func (r Reply) line() string {
	switch {
	case r.Rebooting && r.JSON:
		return r.Message + " (rebooting)"
	case r.RebootPending:
		return r.Message + " (reboot pending)"
	}
	return r.Message
}

// PushRelease is Push, with the seq and the node's status before the push.
func (p *Pusher) PushRelease(ctx context.Context, host string, kind Kind, payload []byte) (Pushed, error) {
	var out Pushed
	if kind == Firmware {
		return out, fmt.Errorf("firmware goes to /ota, not here")
	}
	st, err := p.Status(ctx, host)
	if err != nil {
		return out, err
	}
	out.Before = st
	if err := p.trusted(host, st); err != nil {
		return out, err
	}
	if st.Image == "" {
		return out, fmt.Errorf("%s runs firmware from before chip images: update its firmware first", host)
	}
	if _, ok := st.Seq[kind.String()]; !ok {
		return out, fmt.Errorf("%s doesn't take %s releases: update its firmware first", host, kind)
	}
	node, seq, err := p.target(host, kind, st)
	if err != nil {
		return out, err
	}
	hdr, err := Header(p.Key, kind, p.KeyID, node, st.Image, seq, payload)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+host+"/release",
		bytes.NewReader(append(hdr, payload...)))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := p.client().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	reply := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s %s seq %d rejected: %s %s", host, kind, seq, resp.Status, reply)
	}
	out.Seq = seq
	out.Node = ParseReply(reply)
	out.Reply = fmt.Sprintf("%s seq %d: %s", kind, seq, out.Node.line())
	return out, nil
}
