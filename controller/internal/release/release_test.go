package release

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/pins"
)

// vectors reads firmware/tests/release_vectors.h: releases signed by tools/release.py,
// which the node's C code checks too.
func vectors(t *testing.T) map[string][]byte {
	t.Helper()
	b, err := os.ReadFile("../../../firmware/tests/release_vectors.h")
	if err != nil {
		t.Skip("no firmware/tests/release_vectors.h:", err)
	}
	out := map[string][]byte{}
	re := regexp.MustCompile(`static const uint8_t (\w+)\[\d+\] = \{([^}]*)\};`)
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		var v []byte
		for _, x := range strings.Split(m[2], ",") {
			h, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(x), "0x"))
			if err != nil || len(h) != 1 {
				t.Fatalf("%s: bad byte %q", m[1], x)
			}
			v = append(v, h[0])
		}
		out[m[1]] = v
	}
	return out
}

// The manifests are byte for byte what the Python tool signs, and its signatures verify.
func TestMatchesPython(t *testing.T) {
	v := vectors(t)
	node, _ := ParseMAC("30:ed:a0:00:00:01")
	if !bytes.Equal(node[:], v["V_NODE"]) {
		t.Fatalf("node %x", node)
	}
	for _, c := range []struct {
		name, payload, key string
		kind               Kind
		keyID              uint8
		target             [6]byte
		seq                uint64
	}{
		{"V_FW", "V_FW_PAYLOAD", "V_KEY0", Firmware, KeyRelease, node, 1000},
		{"V_BL", "V_BL_PAYLOAD", "V_KEY1", Blocklist, KeyRecovery, AnyNode, 2000},
		{"V_CFG", "V_CFG_PAYLOAD", "V_KEY0", Config, KeyRelease, node, 3000},
	} {
		m, err := Manifest(c.kind, c.keyID, c.target, "test-board", c.seq, v[c.payload])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m, v[c.name][:ManifestLen]) {
			t.Errorf("%s: manifest differs from the Python tool's\n got %x\nwant %x", c.name, m, v[c.name][:ManifestLen])
		}
		if !Verify(v[c.key], v[c.name]) {
			t.Errorf("%s: Python signature doesn't verify", c.name)
		}
	}
	if Verify(v["V_KEY0"], v["V_BL"]) {
		t.Error("verified with the wrong key")
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignAndLoad(t *testing.T) {
	k := testKey(t)
	payload := []byte("ESPDNSBL and the rest")
	h, err := Header(k, Overrides, KeyRelease, AnyNode, "esp32p4-rev1", 42, payload)
	if err != nil || len(h) != HeaderLen {
		t.Fatal(len(h), err)
	}
	pub := PublicRaw(k)
	if len(pub) != 65 || pub[0] != 4 || !Verify(pub, h) {
		t.Fatal("own signature doesn't verify")
	}
	for i := range HeaderLen {
		c := bytes.Clone(h)
		c[i] ^= 1
		if Verify(pub, c) {
			t.Fatalf("flipped byte %d still verifies", i)
		}
	}
	if h[8] != 5 || string(h[16:28]) != "esp32p4-rev1" || binary.LittleEndian.Uint64(h[32:]) != 42 {
		t.Errorf("manifest fields: %x", h[:48])
	}
	if _, err := Manifest(Blocklist, 0, AnyNode, "a-name-too-long-for-it", 1, nil); err == nil {
		t.Error("long image name accepted")
	}

	// The PEM the key tools write (PKCS#8) loads back.
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	path := filepath.Join(t.TempDir(), "release.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	k2, err := LoadKey(path)
	if err != nil || !k2.Equal(k) {
		t.Fatal("LoadKey:", err)
	}
	if len(Fingerprint(pub)) != 16 {
		t.Error("fingerprint length")
	}

	// VerifySig: a signature over any bytes, with the key that made it only
	data := []byte("0123  file\n")
	sig, err := Sign(k, data)
	if err != nil || !VerifySig(pub, data, sig) {
		t.Fatal("VerifySig: own signature doesn't verify", err)
	}
	if VerifySig(PublicRaw(testKey(t)), data, sig) || VerifySig(pub, append(data, ' '), sig) ||
		VerifySig(pub, data, sig[:SigLen-1]) || VerifySig(pub[:64], data, sig) {
		t.Error("VerifySig: another key, other data, a short signature or a short key verifies")
	}
}

func TestSeqAndPause(t *testing.T) {
	now := time.UnixMilli(1_800_000_000_000)
	// The clock, or one above the last; up to SeqAhead past the clock and no further, so a
	// record (or a /status, a plan) near 2^64 never gets a seq that leaves none above it.
	ahead := uint64(1_800_000_000_000 + SeqAhead.Milliseconds())
	for _, c := range []struct {
		last, want uint64
		ok         bool
	}{
		{0, 1_800_000_000_000, true},
		{5, 1_800_000_000_000, true},
		{1_800_000_000_000, 1_800_000_000_001, true},
		{ahead - 1, ahead, true},
		{ahead, 0, false},
		{1 << 62, 0, false},
		{math.MaxUint64 - 1, 0, false},
		{math.MaxUint64, 0, false},
	} {
		got, err := NextSeq(c.last, now)
		if got != c.want || (err == nil) != c.ok {
			t.Errorf("NextSeq(%d): %d %v", c.last, got, err)
		}
	}
	if got, err := NextSeq(0, time.UnixMilli(-5)); got != 1 || err != nil {
		t.Errorf("NextSeq before 1970: %d %v", got, err)
	}
	if p := PausePayload(90 * time.Minute); !bytes.Equal(p, []byte{1, 0x18, 0x15, 0, 0}) {
		t.Errorf("pause payload %x", p)
	}
	if p := PausePayload(500 * time.Millisecond); !bytes.Equal(p, []byte{1, 1, 0, 0, 0}) {
		t.Errorf("sub-second pause payload %x", p)
	}
	if p := PausePayload(-time.Second); !bytes.Equal(p, []byte{1, 0, 0, 0, 0}) {
		t.Errorf("resume payload %x", p)
	}
	if p := IdentifyPayload(30 * time.Second); !bytes.Equal(p, []byte{2, 30, 0, 0, 0}) {
		t.Errorf("identify payload %x", p)
	}
	if p := IdentifyPayload(1500 * time.Millisecond); !bytes.Equal(p, []byte{2, 2, 0, 0, 0}) {
		t.Errorf("identify rounds up: %x", p)
	}
	if p := IdentifyPayload(48 * time.Hour); !bytes.Equal(p, []byte{2, 0x10, 0x0e, 0, 0}) {
		t.Errorf("identify capped at an hour: %x", p)
	}
	if p := IdentifyPayload(0); !bytes.Equal(p, []byte{2, 0, 0, 0, 0}) {
		t.Errorf("identify stop payload %x", p)
	}
	if p := FlushPayload(); !bytes.Equal(p, []byte{3}) {
		t.Errorf("flush payload %x", p)
	}
	if p := IdentifyPayload(30 * time.Second); !bytes.Equal(p, []byte{2, 30, 0, 0, 0}) {
		t.Errorf("identify payload %x", p)
	}
	if p := IdentifyPayload(1500 * time.Millisecond); !bytes.Equal(p, []byte{2, 2, 0, 0, 0}) {
		t.Errorf("identify rounds up: %x", p)
	}
	if p := IdentifyPayload(48 * time.Hour); !bytes.Equal(p, []byte{2, 0x10, 0x0e, 0, 0}) {
		t.Errorf("identify capped at an hour: %x", p)
	}
	if p := IdentifyPayload(0); !bytes.Equal(p, []byte{2, 0, 0, 0, 0}) {
		t.Errorf("identify stop payload %x", p)
	}
	if p := FlushPayload(); !bytes.Equal(p, []byte{3}) {
		t.Errorf("flush payload %x", p)
	}
	if p, err := RevertPayload(Blocklist); err != nil || !bytes.Equal(p, []byte{5, 4}) {
		t.Errorf("revert blocklist payload %x %v", p, err)
	}
	if p, err := RevertPayload(Overrides); err != nil || !bytes.Equal(p, []byte{5, 5}) {
		t.Errorf("revert overrides payload %x %v", p, err)
	}
	if p, err := RevertPayload(Zones); err != nil || !bytes.Equal(p, []byte{5, 3}) {
		t.Errorf("revert zones payload %x %v", p, err)
	}
	for _, k := range []Kind{Firmware, Config, Control} {
		if _, err := RevertPayload(k); err == nil {
			t.Errorf("revert %s: no error", k)
		}
	}
	// The kinds are firmware/main/release.h's rel_kind_t; identify and flush are commands
	// inside a Control release (block.h BLK_CTL_*), not kinds of their own.
	for i, k := range []Kind{Firmware, Config, Zones, Blocklist, Overrides, Control} {
		if int(k) != i+1 {
			t.Errorf("kind %v is %d, firmware has %d", k, k, i+1)
		}
		if got, err := ParseKind(k.String()); err != nil || got != k {
			t.Errorf("kind %v round trip: %v %v", k, got, err)
		}
	}
}

// A push reads the node's /status and posts a release the node would accept.
func TestPush(t *testing.T) {
	k := testKey(t)
	pub := PublicRaw(k)
	var got []byte
	status := NodeStatus{NodeID: "30:ed:a0:00:00:01", Image: "esp32p4-rev1",
		Keys: []string{Fingerprint(pub), "0000000000000000"},
		Seq:  map[string]uint64{"firmware": 1, "blocklist": 3_000_000_000_000, "overrides": 0, "control": 0}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(status)
		case "/release":
			got, _ = io.ReadAll(r.Body)
			io.WriteString(w, "ok, applied\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ledger := pinned(t, host, status.NodeID)
	p := &Pusher{Key: k, KeyID: KeyRelease, Pins: ledger, Now: func() time.Time { return time.UnixMilli(1_800_000_000_000) }}
	payload := []byte("ESPDNSBL list bytes")

	reply, err := p.Push(context.Background(), host, Blocklist, payload)
	if err != nil || !strings.Contains(reply, "ok, applied") {
		t.Fatal(reply, err)
	}
	if len(got) != HeaderLen+len(payload) || !Verify(pub, got) || !bytes.Equal(got[HeaderLen:], payload) {
		t.Fatalf("posted %d bytes, signature ok %v", len(got), Verify(pub, got))
	}
	// The seq is the signer's clock (its record had none), not one above the node's /status.
	node, _ := ParseMAC(status.NodeID)
	want, _ := Manifest(Blocklist, KeyRelease, node, "esp32p4-rev1", 1_800_000_000_000, payload)
	if !bytes.Equal(got[:ManifestLen], want) {
		t.Errorf("manifest %x, want %x", got[:ManifestLen], want)
	}
	if s, _ := ledger.Seq(status.NodeID, "blocklist"); s != 1_800_000_000_000 {
		t.Errorf("recorded seq %d", s)
	}
	// The next, in the same millisecond: one above the record.
	if r, err := p.PushRelease(context.Background(), host, Blocklist, payload); err != nil || r.Seq != 1_800_000_000_001 {
		t.Errorf("second push: %+v %v", r, err)
	}

	// A key the node doesn't trust, or a node that doesn't take the kind, is refused here.
	p2 := &Pusher{Key: testKey(t), Pins: ledger}
	if _, err := p2.Push(context.Background(), host, Overrides, payload); err == nil || !strings.Contains(err.Error(), "trusts") {
		t.Error("untrusted key:", err)
	}
	delete(status.Seq, "control")
	if _, err := p.Push(context.Background(), host, Control, PausePayload(time.Minute)); err == nil {
		t.Error("pushed a kind the node doesn't list")
	}
	if _, err := p.Push(context.Background(), host, Firmware, payload); err == nil {
		t.Error("firmware over /release")
	}
}

// pinned is a record in a scratch data directory with node id pinned to host.
func pinned(t *testing.T, host, id string) *pins.Ledger {
	t.Helper()
	l := pins.Open(t.TempDir())
	if _, err := l.Pin(id, host); err != nil {
		t.Fatal(err)
	}
	return l
}

// Issue #55: what a /status says never picks the node a release is signed for, or its seq.
// Anything answering on a node's address can send one: a seq near 2^64 in it would have
// had the signer issue the last seq there is, and the real node, given that release,
// refuse every release of the kind after it.
func TestPushIgnoresStatusIDAndSeq(t *testing.T) {
	k := testKey(t)
	pub := PublicRaw(k)
	var got [][]byte
	status := NodeStatus{NodeID: "30:ed:a0:00:00:01", Image: "esp32p4-rev1", Keys: []string{Fingerprint(pub), "x"},
		Seq: map[string]uint64{"firmware": math.MaxUint64 - 1, "config": math.MaxUint64 - 1, "control": 1 << 62}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(status)
		case "/release", "/ota":
			b, _ := io.ReadAll(r.Body)
			got = append(got, b)
			io.WriteString(w, "ok\n")
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	now := time.UnixMilli(1_800_000_000_000)
	ledger := pinned(t, host, "30:ed:a0:00:00:01")
	p := &Pusher{Key: k, Pins: ledger, Now: func() time.Time { return now }}

	// The spoofed seqs: signed with the clock, as if they weren't there.
	for _, kind := range []Kind{Config, Control} {
		r, err := p.PushRelease(context.Background(), host, kind, []byte("x"))
		if err != nil || r.Seq != 1_800_000_000_000 {
			t.Fatalf("%s: %+v %v", kind, r, err)
		}
	}
	if r, err := p.PushFirmware(context.Background(), host, appImage(), FirmwareOptions{Image: "esp32p4-rev1"}); err != nil ||
		r.Seq != 1_800_000_000_000 {
		t.Fatalf("firmware: %+v %v", r, err)
	}
	for _, b := range got {
		if s := binary.LittleEndian.Uint64(b[32:40]); s != 1_800_000_000_000 {
			t.Errorf("signed seq %d", s)
		}
	}

	// A /status that answers as another node: refused, nothing signed or recorded.
	got = nil
	status.NodeID = "30:ed:a0:00:00:02"
	_, err := p.PushRelease(context.Background(), host, Config, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "pinned there") || got != nil {
		t.Fatalf("another node's /status: %v, %d posted", err, len(got))
	}
	if _, err := p.PushFirmware(context.Background(), host, appImage(), FirmwareOptions{Image: "esp32p4-rev1"}); err == nil || got != nil {
		t.Fatalf("firmware for another node's /status: %v", err)
	}
	if s, _ := ledger.Seq("30:ed:a0:00:00:01", "config"); s != 1_800_000_000_000 {
		t.Errorf("config seq recorded %d", s)
	}
	status.NodeID = "30:ed:a0:00:00:01"

	// An address with no node pinned to it, or no record at all: nothing is signed.
	if _, err := (&Pusher{Key: k, Pins: pins.Open(t.TempDir())}).PushRelease(context.Background(), host, Config, []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "not pinned") || got != nil {
		t.Fatalf("not pinned: %v", err)
	}
	if _, err := (&Pusher{Key: k}).PushRelease(context.Background(), host, Config, []byte("x")); err == nil || got != nil {
		t.Fatalf("no record: %v", err)
	}

	// Unadopted (identify on a node not adopted yet): an address with no node pinned is
	// signed for its /status ID, recorded pinned nowhere; one with a node pinned still
	// answers for it alone, and an ID pinned to another address gets nothing.
	own := pins.Open(t.TempDir())
	u := &Pusher{Key: k, Pins: own, Unadopted: true, Now: func() time.Time { return now }}
	if r, err := u.PushRelease(context.Background(), host, Control, []byte("x")); err != nil || r.Seq != 1_800_000_000_000 ||
		len(got) != 1 || !bytes.Equal(got[0][10:16], []byte{0x30, 0xed, 0xa0, 0, 0, 1}) {
		t.Fatalf("unadopted: %+v %v", r, err)
	}
	if s, err := own.Seq("30:ed:a0:00:00:01", "control"); err != nil || s != 1_800_000_000_000 {
		t.Fatalf("its seq recorded: %d %v", s, err)
	}
	if _, err := own.Pinned(host); !errors.Is(err, pins.ErrNotPinned) {
		t.Fatalf("pinned by a push: %v", err)
	}
	got = nil
	if _, err := own.Pin("30:ed:a0:00:00:01", "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.PushRelease(context.Background(), host, Control, []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "pinned to 192.0.2.77") || got != nil {
		t.Fatalf("unadopted, pinned elsewhere: %v", err)
	}
	u.Pins = ledger
	status.NodeID = "30:ed:a0:00:00:02"
	if _, err := u.PushRelease(context.Background(), host, Control, []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "pinned there") || got != nil {
		t.Fatalf("unadopted, another node pinned there: %v", err)
	}
	status.NodeID = "30:ed:a0:00:00:01"

	// A record of its own that went past the clock (a clock set back, a file edited): refused
	// rather than signed above it.
	if err := ledger.SetSeq("30:ed:a0:00:00:01", "zones", math.MaxUint64-1); err != nil {
		t.Fatal(err)
	}
	status.Seq["zones"] = 0
	if _, err := p.PushRelease(context.Background(), host, Zones, []byte("x")); err == nil ||
		!strings.Contains(err.Error(), "past this clock") || got != nil {
		t.Fatalf("record past the clock: %v", err)
	}
}
