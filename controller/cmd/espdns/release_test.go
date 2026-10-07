package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/dist"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// A throwaway release key, its PEM and its public key file as firmware/keys has it
func releaseKey(t *testing.T) (pem []byte, pubFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if pem, err = keys.Encode(k); err != nil {
		t.Fatal(err)
	}
	pubFile = filepath.Join(t.TempDir(), "release.pub")
	os.WriteFile(pubFile, release.PublicRaw(k), 0o644)
	return pem, pubFile
}

// app is an ESP app image as the release reads one: the descriptor's version, no address built in
func app(version string) []byte {
	b := make([]byte, 32+256)
	b[0] = 0xE9
	binary.LittleEndian.PutUint32(b[32:], 0xABCD5432)
	copy(b[48:], version)
	return append(b, "espdns:builtin-address=\x00"...)
}

// One exported chip image for each of the catalog's boards' images
func chipImages(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	for img, chip := range map[string]string{"esp32p4-rev1": "esp32p4", "esp32s3-octal": "esp32s3"} {
		d := filepath.Join(dir, img)
		os.MkdirAll(d, 0o755)
		boot := make([]byte, 32)
		boot[0] = 0xE9
		for n, b := range map[string][]byte{"bootloader.bin": boot, "partitions-8mb.bin": []byte("t8"), "partitions-4mb.bin": []byte("t4"),
			"ota_data_initial.bin": []byte("ota"), "app.bin": app(version)} {
			os.WriteFile(filepath.Join(d, n), b, 0o644)
		}
		info, _ := json.Marshal(map[string]any{"image": img, "chip": chip, "chip_family": "ESP32", "version": version,
			"offsets": map[string]int{"bootloader.bin": 0, "partitions-8mb.bin": 0x8000, "partitions-4mb.bin": 0x8000,
				"ota_data_initial.bin": 0xf000, "app.bin": 0x20000, "board": 0x12000}})
		os.WriteFile(filepath.Join(d, "image.json"), info, 0o644)
	}
	return dir
}

func runRelease(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := cmdRelease(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

// build, then sign with the key on standard input (PEM or base64 of it), verify, import: the
// steps of docs/releasing.md, as the commands run them.
func TestReleaseCommands(t *testing.T) {
	pem, pub := releaseKey(t)
	out := filepath.Join(t.TempDir(), "dist")
	got, err := runRelease(t, "", "build", "-version", "0.0.4", "-images", chipImages(t, "0.0.4"), "-catalog", "../../../boards", "-out", out)
	if err != nil || !strings.Contains(got, filepath.Join(out, dist.SumsFile)) || !strings.Contains(got, "not signed") {
		t.Fatalf("build: %v\n%s", err, got)
	}
	if _, err := runRelease(t, "", "verify", "-dir", out, "-pub", pub); err == nil || !strings.Contains(err.Error(), "isn't signed") {
		t.Fatalf("verify unsigned: %v", err)
	}

	// Another key than -pub's is refused, and nothing signed
	other, _ := releaseKey(t)
	if _, err := runRelease(t, string(other), "sign", "-dir", out, "-pub", pub); err == nil || !strings.Contains(err.Error(), "not the release key") {
		t.Fatalf("sign with another key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, dist.SigFile)); err == nil {
		t.Fatal("signed with another key")
	}
	if _, err := runRelease(t, "", "sign", "-dir", out, "-pub", pub); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("sign with no key: %v", err)
	}
	for _, in := range []string{string(pem), base64.StdEncoding.EncodeToString(pem) + "\n"} {
		got, err = runRelease(t, in, "sign", "-dir", out, "-pub", pub)
		if err != nil || !strings.Contains(got, "signed with the release key") {
			t.Fatalf("sign: %v %s", err, got)
		}
		if strings.Contains(got, strings.TrimSpace(string(pem))) {
			t.Fatal("the key in the output")
		}
	}
	got, err = runRelease(t, "", "verify", "-dir", out, "-pub", pub)
	if err != nil || !strings.Contains(got, "espdns-0.0.4-factory-ws-s3-eth.bin: OK") || !strings.Contains(got, "files as signed") {
		t.Fatalf("verify: %v\n%s", err, got)
	}
	data := t.TempDir()
	got, err = runRelease(t, "", "import", "-dir", out, "-pub", pub, "-data", data)
	if err != nil || !strings.Contains(got, "esp32p4-rev1, esp32s3-octal") {
		t.Fatalf("import: %v %s", err, got)
	}
	if _, err := os.Stat(filepath.Join(data, "firmware", "images", "esp32s3-octal", "image.json")); err != nil {
		t.Error(err)
	}
	if b, err := os.ReadFile(filepath.Join(data, "log", "actions.jsonl")); err != nil || !strings.Contains(string(b), `"release import"`) {
		t.Errorf("import not in the action log: %v %s", err, b)
	}

	// Never while a rollout or a job holds the fleet lock
	lk, err := fleetlock.Acquire(fleetlock.Path(data), fleetlock.Self("test rollout", "rolling"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runRelease(t, "", "import", "-dir", out, "-pub", pub, "-data", data); !errors.Is(err, fleetlock.ErrLocked) {
		t.Errorf("import under the fleet lock: %v", err)
	}
	lk.Release()

	// Changed after signing: verify names the file
	f := filepath.Join(out, "espdns-0.0.4-factory-p4-ip101.bin")
	os.WriteFile(f, []byte("tampered"), 0o644)
	if _, err := runRelease(t, "", "verify", "-dir", out, "-pub", pub); err == nil || !strings.Contains(err.Error(), filepath.Base(f)) {
		t.Errorf("verify tampered: %v", err)
	}
}

func TestReleaseUsage(t *testing.T) {
	_, pub := releaseKey(t)
	short := filepath.Join(t.TempDir(), "short.pub")
	os.WriteFile(short, []byte("not a key"), 0o644)
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "usage"},
		{[]string{"publish"}, "unknown release command"},
		{[]string{"build", "-version", "0.0.4"}, "are required"},
		{[]string{"verify", "-dir", "x"}, "are required"},
		{[]string{"import", "-dir", "x", "-pub", pub}, "-data"},
		{[]string{"verify", "-dir", t.TempDir(), "-pub", short}, "not a raw P-256 public key"},
		{[]string{"verify", "-dir", t.TempDir(), "-pub", pub, "extra"}, "unexpected arguments"},
	} {
		if _, err := runRelease(t, "", c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
}
