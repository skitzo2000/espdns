package zones

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Check says what espdns zones -check says: a line per zone and the bundle within the limit,
// or the first error (a clash with the config, a bundle over the limit).
func TestCheck(t *testing.T) {
	z, err := LoadFile("testdata/home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	set := &Set{Zones: []*Zone{z}}
	ck, err := Check(set, nil, 64)
	if err != nil || len(ck.Lines) != 2 || ck.Lines[0] != "home.example: serial 2026100201, 18 records" ||
		!strings.HasPrefix(ck.Lines[1], "ok: 1 zones, ") || !strings.HasSuffix(ck.Lines[1], "of a 64 KB limit") || len(ck.Payload) == 0 {
		t.Fatalf("%v %+v", err, ck)
	}
	if ck, err := Check(set, nil, -1); err != nil || len(ck.Lines) != 1 || ck.Payload != nil {
		t.Errorf("no bundle: %v %+v", err, ck)
	}
	if _, err := Check(set, nil, 1); err == nil || !strings.Contains(err.Error(), "hosted_zones_kb") {
		t.Errorf("over the limit: %v", err)
	}
	zs := []string{"Home.Example."}
	if _, err := Check(set, &nodecfg.Config{Secondary: &nodecfg.Secondary{Zones: &zs}}, 64); err == nil || !strings.Contains(err.Error(), "secondary or forward") {
		t.Errorf("clash: %v", err)
	}
	if err := set.ClashWith([]string{"other.example", "home.example."}, "a secondary zone of n"); err == nil || !strings.Contains(err.Error(), "a secondary zone of n") {
		t.Errorf("clash with /status: %v", err)
	}
	if _, err := set.Payload("n", release.NodeStatus{}); err == nil || !strings.Contains(err.Error(), "update its firmware") {
		t.Errorf("old firmware: %v", err)
	}
	if b, err := set.Payload("n", release.NodeStatus{Hosted: &release.HostedStatus{LimitBytes: 64 << 10}}); err != nil || !bytes.Equal(b, ck.Payload) {
		t.Errorf("payload: %v", err)
	}
	// A forward zone the node reports (forward_zones): refused; none reported ([]): fine.
	var fst release.NodeStatus
	json.Unmarshal([]byte(`{"hosted":{"limit_bytes":65536},"forward_zones":[{"name":"corp.example","forwarder":"192.0.2.53"},{"name":"HOME.example.","forwarder":"192.0.2.53"}]}`), &fst)
	if _, err := set.Payload("n", fst); err == nil || !strings.Contains(err.Error(), "home.example is both a hosted zone and a forward zone of n (its /status)") {
		t.Errorf("forward zone in /status: %v", err)
	}
	json.Unmarshal([]byte(`{"hosted":{"limit_bytes":65536},"forward_zones":[]}`), &fst)
	if _, err := set.Payload("n", fst); err != nil || fst.ForwardZones == nil {
		t.Errorf("no forward zones (%v): %v", fst.ForwardZones, err)
	}
	// What a push of the set drops: the zones the node serves that it doesn't have.
	var hst release.NodeStatus
	json.Unmarshal([]byte(`{"hosted":{"zones":[{"name":"home.example"},{"name":"Other.Example."},{"name":"b.example"}]}}`), &hst)
	if d := set.Drops(hst); strings.Join(d, ",") != "b.example,other.example" {
		t.Errorf("drops %v", d)
	}
	if d := set.Drops(release.NodeStatus{}); d != nil {
		t.Errorf("drops from old firmware %v", d)
	}
	// A forward zone in /status as firmware reports it ({"name", "forwarder"}); a plain name
	// is not a shape the firmware sends.
	var st release.NodeStatus
	json.Unmarshal([]byte(`{"hosted":{"state":"on","limit_bytes":65536},"forward_zones":[{"name":"Home.Example","forwarder":"192.0.2.53"}]}`), &st)
	if len(st.ForwardZones) != 1 || st.ForwardZones[0].Forwarder != "192.0.2.53" {
		t.Errorf("forward_zones: %+v", st.ForwardZones)
	}
	if _, err := set.Payload("n", st); err == nil || !strings.Contains(err.Error(), "a forward zone of n") {
		t.Errorf("forward zone clash: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"forward_zones":["home.example"]}`), &st); err == nil {
		t.Error("a plain name taken as a forward zone")
	}
	// The records as text, as the node holds them.
	tx := z.Texts(0)
	if len(tx) != 18 || tx[0].Owner != "*.dev.home.example." || tx[0].Type != "A" || tx[0].TTL != 300 || tx[0].Data != "192.0.2.40" {
		t.Errorf("texts %+v", tx[:2])
	}
	found := false
	for _, r := range tx {
		if r.Type == "SRV" && r.Owner == "_http._tcp.home.example." && strings.TrimSpace(r.Data) == "0 5 80 www.home.example." {
			found = true
		}
	}
	if !found || len(z.Texts(3)) != 3 {
		t.Errorf("texts %+v", tx)
	}
}

func TestNextSerial(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		old   uint32
		above []uint32
		want  uint32
	}{
		{2026100201, nil, 2026100301},
		{2026100305, nil, 2026100306},
		{2026100301, []uint32{2026100307}, 2026100308},
		{7, nil, 8},
		{7, []uint32{12}, 13},
		{4294967295, nil, 1},
		{2026100399, nil, 2026100400}, // the 99th today: on into tomorrow's first
		{5, []uint32{4294967290}, 6},  // 5 is past 4294967290, wrapped
		{4294967290, []uint32{5}, 6},
	} {
		if got := NextSerial(c.old, c.above, now); got != c.want {
			t.Errorf("%d %v: %d, want %d", c.old, c.above, got, c.want)
		}
		for _, a := range append(c.above, c.old) {
			if got := NextSerial(c.old, c.above, now); !SerialAbove(got, a) {
				t.Errorf("%d %v: %d not above %d", c.old, c.above, got, a)
			}
		}
	}
}

// SetSerial changes the serial's token and nothing else: comments, layout, the rest kept;
// a text where it can't be found is refused, not guessed at.
func TestSetSerial(t *testing.T) {
	b, err := os.ReadFile("testdata/home.example.zone")
	if err != nil {
		t.Fatal(err)
	}
	out, err := SetSerial("home.example", b, 2026100301)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != strings.Replace(string(b), "2026100201", "2026100301", 1) {
		t.Errorf("changed more than the serial:\n%s", out)
	}
	multi := "$TTL 300\n; the SOA serial (2026100201) is below\nsoa IN A 192.0.2.1\n" +
		"@ IN SOA ns1 hostmaster (\n  2026100201 ; serial\n  3600 600 86400 300 )\n@ IN NS ns1\nns1 IN A 192.0.2.2\n" +
		"t IN TXT \"SOA ns1 hostmaster 5\"\n"
	out, err = SetSerial("x.example", []byte(multi), 2026100302)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != strings.Replace(multi, "  2026100201 ; serial", "  2026100302 ; serial", 1) {
		t.Errorf("multi-line:\n%s", out)
	}
	if _, err := SetSerial("x.example", []byte("@ IN NS ns1\n"), 5); err == nil {
		t.Error("no SOA: set")
	}
	if _, err := SetSerial("x.example", []byte("@ IN SOA ns1 hostmaster 1 2 3 4 5\n@ IN NS ns1\nns1 IN A 192.0.2.1\nbad IN TYPE65534 \\# 0\n"), 5); err == nil {
		t.Error("a zone that doesn't parse: set")
	}
}
