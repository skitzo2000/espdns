package fleet

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/memplan"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// realList is the header of the 2.6M-entry list of October 2026 and its length, from the
// shared placement vectors (firmware/tests/place_vectors.json).
func realList(t *testing.T) ([]byte, int64) {
	raw, err := os.ReadFile("../../../firmware/tests/place_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vec []struct {
		Name    string `json:"name"`
		Header  string `json:"header"`
		FileLen int64  `json:"file_len"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	for _, v := range vec {
		if strings.HasPrefix(v.Name, "the real list") {
			h, err := hex.DecodeString(v.Header)
			if err != nil {
				t.Fatal(err)
			}
			return h, v.FileLen
		}
	}
	t.Fatal("no real list in the vectors")
	return nil, 0
}

func n64(v int64) *int64 { return &v }

// The two production nodes, as they report themselves.
func p4Status(list release.ListStatus) release.NodeStatus {
	return release.NodeStatus{Board: "p4-ip101", Memory: &release.MemoryStatus{Board: memplan.Board{PSRAMKB: 32768,
		BlocklistKB: 20480, BlocklistIndexKB: 160}}, Blocking: &release.BlockingStatus{List: list}}
}

func s3Status() release.NodeStatus {
	return release.NodeStatus{Board: "ws-s3-eth", Memory: &release.MemoryStatus{Board: memplan.Board{PSRAMKB: 8192,
		BlocklistKB: 2048}}, Blocking: &release.BlockingStatus{}}
}

// Where the real list goes on each production node, or why it doesn't.
func TestListPlacement(t *testing.T) {
	hdr, size := realList(t)
	// The S3: neither the whole table (RAM tier) nor the front and index (SD tier) fit.
	_, err := ListPlacement("192.0.2.252", release.Blocklist, hdr, size, s3Status())
	want := "192.0.2.252: the list needs 4149 KB even in the SD tier (7993 KB in the RAM tier), board ws-s3-eth's " +
		"blocking memory (memory.blocklist_kb) is 2048 KB, so the node would refuse it: leave it out of the rollout, " +
		"or give it a smaller list"
	if err == nil || err.Error() != want {
		t.Fatalf("%v\nwant %s", err, want)
	}
	// The P4 holding the same list in the RAM tier, its index in internal RAM: a live swap,
	// the new copy's index with the list (the old one's still holds the index share), as
	// the node did it. From firmware that says where the bytes are, and estimated from
	// firmware that doesn't.
	on := release.ListStatus{State: "on", Tier: "ram", Bytes: 8184800}
	split := on
	split.DataBytes, split.InternalBytes = n64(8058880), n64(125920)
	for _, l := range []release.ListStatus{split, on} {
		got, err := ListPlacement("192.0.2.253", release.Blocklist, hdr, size, p4Status(l))
		want := "RAM tier, live swap; its index with the list, not in internal RAM, until a reboot"
		if l.DataBytes == nil {
			want += "; estimated: its firmware doesn't say where its lists' indexes are"
		}
		if err != nil || got != want {
			t.Fatalf("%q, %v\nwant %q", got, err, want)
		}
	}
	// Nothing loaded: the index goes to internal RAM.
	if got, err := ListPlacement("p4", release.Blocklist, hdr, size, p4Status(release.ListStatus{State: "off"})); err != nil ||
		got != "RAM tier, live swap" {
		t.Fatalf("%q, %v", got, err)
	}
	// A 14 MB list held: the new one fits only once it is gone.
	big := release.ListStatus{State: "on", Tier: "ram", Bytes: 14 << 20, DataBytes: n64(14 << 20), InternalBytes: n64(0)}
	if got, err := ListPlacement("p4", release.Blocklist, hdr, size, p4Status(big)); err != nil ||
		got != "RAM tier, at the next reboot: two copies don't fit" {
		t.Fatalf("%q, %v", got, err)
	}
	// Overrides from firmware that doesn't say where their index is: counted in internal RAM,
	// the list fits no tier; counted with the overrides, the SD tier. Not refused: the node
	// decides.
	ovrOn := release.ListStatus{State: "on", Tier: "ram", Bytes: 1040000}
	tight := release.NodeStatus{Board: "p4-small", Memory: &release.MemoryStatus{Board: memplan.Board{PSRAMKB: 8192,
		BlocklistKB: 4096, BlocklistIndexKB: 64}}, Blocking: &release.BlockingStatus{Overrides: ovrOn}}
	edge, edgeLen := testList(3<<20, 7000)
	if got, err := ListPlacement("p4", release.Blocklist, edge, edgeLen, tight); err != nil ||
		got != "SD tier, live swap; estimated: its firmware doesn't say where its lists' indexes are" {
		t.Fatalf("%q, %v", got, err)
	}
	// Said by the node, the same overrides in internal RAM: refused.
	ovrOn.DataBytes, ovrOn.InternalBytes = n64(1040000-16000), n64(16000)
	tight.Blocking.Overrides = ovrOn
	if _, err := ListPlacement("p4", release.Blocklist, edge, edgeLen, tight); err == nil ||
		!strings.Contains(err.Error(), "1000 KB of it taken by the overrides") {
		t.Fatal(err)
	}
	// Overrides that don't fit next to what the node holds.
	tight.Blocking.List = release.ListStatus{State: "on", Tier: "sd", Bytes: 3050 << 10, DataBytes: n64(3050 << 10),
		InternalBytes: n64(0)}
	ovrFile, ovrLen := testList(64<<10, 20)
	if _, err := ListPlacement("p4", release.Overrides, ovrFile, ovrLen, tight); err == nil || err.Error() !=
		"p4: the overrides need 64 KB in the RAM tier, board p4-small's blocking memory (memory.blocklist_kb) is "+
			"4096 KB, 4050 KB of it taken by the lists it holds, so the node would refuse it: leave it out of the "+
			"rollout, or give it fewer overrides" {
		t.Fatal(err)
	}
	// Firmware from before the memory plan: not checked, the node decides.
	if got, err := ListPlacement("old", release.Blocklist, hdr, size, release.NodeStatus{}); got != "" || err != nil {
		t.Fatalf("%q, %v", got, err)
	}
	// Overrides: the RAM tier next to the list, at most 1 MB.
	small, smallLen := testList(64<<10, 20)
	if got, err := ListPlacement("p4", release.Overrides, small, smallLen, p4Status(split)); err != nil || got != "RAM tier, live" {
		t.Fatalf("%q, %v", got, err)
	}
	if _, err := ListPlacement("p4", release.Overrides, hdr, size, p4Status(split)); err == nil ||
		!strings.Contains(err.Error(), "a node takes at most 1024 KB") {
		t.Fatal(err)
	}
}

// testList is a list file's header with front bytes before its one table's sectors, and the
// file's length.
func testList(front, sectors int) ([]byte, int64) {
	h := make([]byte, 160)
	copy(h, "ESPDNSBL")
	h[8], h[9] = 2, 44
	binary.LittleEndian.PutUint32(h[32:], uint32(100*sectors))
	binary.LittleEndian.PutUint32(h[36:], uint32(sectors))
	binary.LittleEndian.PutUint32(h[40:], 160)
	binary.LittleEndian.PutUint32(h[44:], uint32(front))
	return h, int64(front + 512*sectors)
}

// A list that fits no tier on a node: the rollout refuses before touching any node, naming
// the node. A node on firmware from before the memory plan isn't checked. The dry run says
// where the list goes on each node.
func TestRolloutListTooBig(t *testing.T) {
	w := newWorld(t)
	a, b := w.node(true), w.node(true)
	hdr, size := testList(200<<10, 400) // a 200 KB front, 200 KB of sectors
	payload := append(hdr, make([]byte, int(size)-len(hdr))...)
	ch := Change{Kind: release.Blocklist, Payload: func(context.Context, string, release.NodeStatus) ([]byte, error) {
		return payload, nil
	}}
	board := func(kb int) map[string]any {
		return map[string]any{"board": map[string]any{"psram_kb": 8192, "blocklist_kb": kb, "blocklist_index_kb": 0}}
	}
	a.memory, b.memory = board(2048), board(128)
	res, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch)
	if err == nil || !strings.HasPrefix(err.Error(), b.host+": the list needs 204 KB even in the SD tier") ||
		!strings.Contains(err.Error(), "(memory.blocklist_kb) is 128 KB") {
		t.Fatal(err)
	}
	if len(w.pushes()) != 0 || !slices.Equal(res.Left, []string{a.host, b.host}) {
		t.Fatalf("pushes %v, result %+v", w.pushes(), res)
	}
	// On firmware from before the memory plan, the node decides.
	b.memory = nil
	if _, err := w.client().Rollout(context.Background(), fastPlan(a.host, b.host), ch); err != nil {
		t.Fatal(err)
	}
	if len(w.pushes()) != 2 {
		t.Fatal(w.pushes())
	}
	// The dry run: where it goes on each node.
	b.memory, b.blocking = board(512), map[string]any{"list": map[string]any{"state": "on", "tier": "ram",
		"bytes": 400 << 10, "data_bytes": 400 << 10, "internal_bytes": 0}}
	var mu sync.Mutex
	var logs []string
	c := w.client()
	c.Logf = func(f string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	p := fastPlan(a.host, b.host)
	p.DryRun = true
	if _, err := c.Rollout(context.Background(), p, ch); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{a.host + ": would push blocklist now (RAM tier, live swap)",
		b.host + ": would push blocklist now (RAM tier, at the next reboot: two copies don't fit)"} {
		if !slices.Contains(logs, want) {
			t.Errorf("no %q in %q", want, logs)
		}
	}
}
