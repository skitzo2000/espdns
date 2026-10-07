package release

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// appImage is an app image with a descriptor, as ESP-IDF lays it out.
func appImage() []byte {
	b := make([]byte, 1024)
	b[0] = 0xE9
	d := b[appDescOff:]
	binary.LittleEndian.PutUint32(d, 0xABCD5432)
	copy(d[16:], "v0.2.0")
	copy(d[48:], "dns2")
	copy(d[80:], "18:35:05")
	copy(d[96:], "Oct  2 2026")
	copy(d[144:], []byte{0xe3, 0x9e, 0x79, 0x9e, 0x00, 0x12, 0x4e, 0x2d, 0xff})
	return b
}

func TestParseAppDesc(t *testing.T) {
	d, err := ParseAppDesc(appImage())
	if err != nil || d.Version != "v0.2.0" || d.Project != "dns2" || d.Built != "Oct  2 2026 18:35:05" ||
		d.ElfSHA256 != "e39e799e00124e2d" {
		t.Fatalf("%+v %v", d, err)
	}
	bad := appImage()
	bad[appDescOff] = 0
	if _, err := ParseAppDesc(bad); err == nil {
		t.Fatal("no descriptor accepted")
	}
}

// The reboot command: 04, u32 LE milliseconds, flags (bit 0: only if a reboot is pending).
func TestRebootPayload(t *testing.T) {
	if p := RebootPayload(1500*time.Millisecond, true); !bytes.Equal(p, []byte{4, 0xdc, 0x05, 0, 0, 1}) {
		t.Fatalf("%x", p)
	}
	if p := RebootPayload(-time.Second, false); !bytes.Equal(p, []byte{4, 0, 0, 0, 0, 0}) {
		t.Fatalf("%x", p)
	}
}

func TestParseReply(t *testing.T) {
	r := ParseReply(`{"ok":true,"message":"ok, config seq 5 stored","reboot_pending":true,"rebooting":false}`)
	if !r.JSON || !r.RebootPending || r.Rebooting || r.Message != "ok, config seq 5 stored" {
		t.Fatalf("%+v", r)
	}
	r = ParseReply("ok, config seq 5 stored; rebooting to apply it (on trial: ...)")
	if r.JSON || r.RebootPending || !r.Rebooting {
		t.Fatalf("%+v", r)
	}
	if r := ParseReply("ok, blocklist seq 7 applied live"); r.Rebooting || r.RebootPending {
		t.Fatalf("%+v", r)
	}
}

// A firmware push is signed for the node's chip image and staged with X-OTA-Reboot: later;
// the wrong image or an untrusted key is refused before anything is sent.
func TestPushFirmware(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var got []byte
	var later string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"node_id": "30:ed:a0:00:00:01", "image": "esp32p4-rev1",
				"keys": []string{Fingerprint(PublicRaw(k)), "x"}, "seq": map[string]uint64{"firmware": 7}})
		case "/ota":
			got, _ = io.ReadAll(r.Body)
			later = r.Header.Get("X-OTA-Reboot")
			w.Write([]byte(`{"ok":true,"message":"ok, firmware staged","reboot_pending":true,"rebooting":false}`))
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	ledger := pinned(t, host, "30:ed:a0:00:00:01")
	p := &Pusher{Key: k, Pins: ledger, Now: func() time.Time { return time.UnixMilli(1_800_000_000_000) }}
	img := appImage()
	if _, err := p.PushFirmware(context.Background(), host, img, FirmwareOptions{Image: "esp32s3-octal"}); err == nil || got != nil {
		t.Fatal("wrong chip image pushed:", err)
	}
	r, err := p.PushFirmware(context.Background(), host, img, FirmwareOptions{Image: "esp32p4-rev1", Later: true})
	if err != nil || !r.Node.RebootPending || later != "later" || r.Seq != 1_800_000_000_000 {
		t.Fatalf("%+v %v %q", r, err, later)
	}
	if !Verify(PublicRaw(k), got) || Kind(got[8]) != Firmware || string(got[16:28]) != "esp32p4-rev1" ||
		!bytes.Equal(got[HeaderLen:], img) {
		t.Fatal("bad release")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got = nil
	if _, err := (&Pusher{Key: other, Pins: ledger}).PushFirmware(context.Background(), host, img, FirmwareOptions{Image: "esp32p4-rev1"}); err == nil ||
		!strings.Contains(err.Error(), "fingerprint") || got != nil {
		t.Fatal(err)
	}
}

// pythonManifest is the manifest firmware/tools/ota_push.py signs for the same push, from
// tools/release.py itself (its signing imports stubbed: the manifest needs only hashlib).
func pythonManifest(t *testing.T, nodeID, name string, seq uint64, image []byte) []byte {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3")
	}
	tools, _ := filepath.Abs("../../../firmware/tools")
	if _, err := os.Stat(filepath.Join(tools, "release.py")); err != nil {
		t.Skip("no firmware/tools/release.py")
	}
	img := filepath.Join(t.TempDir(), "app.bin")
	if err := os.WriteFile(img, image, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
import sys, types
for m in ["cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives",
          "cryptography.hazmat.primitives.asymmetric", "cryptography.hazmat.primitives.asymmetric.utils"]:
    sys.modules.setdefault(m, types.ModuleType(m))
p = sys.modules["cryptography.hazmat.primitives"]
p.hashes = p.serialization = None
sys.modules["cryptography.hazmat.primitives.asymmetric"].ec = None
sys.modules["cryptography.hazmat.primitives.asymmetric.utils"].decode_dss_signature = None
sys.path.insert(0, sys.argv[1])
import release
image = open(sys.argv[2], "rb").read()
m = release.manifest("firmware", release.KEY_RELEASE, release.parse_mac(sys.argv[3]), sys.argv[4], int(sys.argv[5]), image)
sys.stdout.write(m.hex())
`
	out, err := exec.Command(py, "-c", script, tools, img, nodeID, name, strconv.FormatUint(seq, 10)).Output()
	if err != nil {
		t.Fatalf("python: %v", err)
	}
	m, err := hex.DecodeString(string(out))
	if err != nil || len(m) != ManifestLen {
		t.Fatalf("python manifest %q: %v", out, err)
	}
	return m
}

// The firmware release PushFirmware posts starts with the manifest ota_push.py would sign
// for the same node, name, seq and image: for a chip image, and for a transitional image
// named by its board.
func TestPushFirmwareMatchesPython(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, c := range []struct{ image, board, want string }{
		{"esp32p4-rev1", "", "esp32p4-rev1"},
		{"", "p4-ip101", "p4-ip101"},
	} {
		var got []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/status":
				st := map[string]any{"node_id": "30:ed:a0:00:00:01", "board": "p4-ip101",
					"keys": []string{Fingerprint(PublicRaw(k)), "x"}, "seq": map[string]uint64{"firmware": 1759400000000}}
				if c.image != "" {
					st["image"] = c.image
				}
				json.NewEncoder(w).Encode(st)
			case "/ota":
				got, _ = io.ReadAll(r.Body)
				w.Write([]byte("ok, rebooting\n"))
			}
		}))
		host := strings.TrimPrefix(srv.URL, "http://")
		img := appImage()
		p := &Pusher{Key: k, Pins: pinned(t, host, "30:ed:a0:00:00:01"), Now: func() time.Time { return time.UnixMilli(1759400000001) }}
		r, err := p.PushFirmware(context.Background(), host, img, FirmwareOptions{Image: "esp32p4-rev1", Board: c.board})
		srv.Close()
		if err != nil || r.Seq != 1759400000001 || !r.Node.Rebooting || r.Node.JSON {
			t.Fatalf("%s: %+v %v", c.want, r, err)
		}
		want := pythonManifest(t, "30:ed:a0:00:00:01", c.want, r.Seq, img)
		if !bytes.Equal(got[:ManifestLen], want) {
			t.Errorf("%s: manifest differs from ota_push.py's\n got %x\nwant %x", c.want, got[:ManifestLen], want)
		}
		if !Verify(PublicRaw(k), got) || !bytes.Equal(got[HeaderLen:], img) {
			t.Errorf("%s: bad signature or image", c.want)
		}
	}
}

// The address built into a firmware image, behind the firmware's marker (main/cfg.h).
func TestBuiltinAddress(t *testing.T) {
	for _, c := range []struct {
		image string
		addr  string
		known bool
	}{
		{"\xE9...espdns:builtin-address=192.0.2.53\x00...", "192.0.2.53", true},
		{"\xE9...espdns:builtin-address=\x00...", "", true},
		{"\xE9... an image from before the marker", "", false},
		{"\xE9...espdns:builtin-address=192.0.2.53", "", false},                // no end
		{"\xE9...espdns:builtin-address=not-an-address-at-all\x00", "", false}, // too long
	} {
		if a, k := BuiltinAddress([]byte(c.image)); a != c.addr || k != c.known {
			t.Errorf("%q: %q %v", c.image, a, k)
		}
	}
}
