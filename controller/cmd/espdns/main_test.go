package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/version"
)

// Each control command sends the payload firmware/main/blocking.c (apply_control) reads.
func TestControlPayload(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		d    time.Duration
		kind string
		want []byte
	}{
		{"pause", 90 * time.Minute, "", []byte{1, 0x18, 0x15, 0, 0}},
		{"pause", 0, "", []byte{1, 0, 0, 0, 0}},
		{"pause", 7 * 24 * time.Hour, "", []byte{1, 0x80, 0x3a, 0x09, 0}}, // a week, the most

		{"identify", 30 * time.Second, "", []byte{2, 30, 0, 0, 0}},
		{"identify", 0, "", []byte{2, 0, 0, 0, 0}},
		{"flush", 0, "", []byte{3}},
		{"flush", time.Minute, "", []byte{3}},
		{"revert", 0, "blocklist", []byte{5, 4}},
		{"revert", 0, "overrides", []byte{5, 5}},
		{"revert", 0, "zones", []byte{5, 3}},
	} {
		got, err := controlPayload(c.cmd, c.d, c.kind)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s %v %s: %x %v, want %x", c.cmd, c.d, c.kind, got, err, c.want)
		}
	}
	for _, kind := range []string{"config", "firmware", "control", "nonsense"} {
		if _, err := controlPayload("revert", 0, kind); err == nil {
			t.Errorf("revert -kind %s accepted", kind)
		}
	}
	for _, d := range []time.Duration{7*24*time.Hour + time.Second, -time.Second} {
		if _, err := controlPayload("pause", d, ""); err == nil {
			t.Errorf("pause -for %v accepted", d)
		}
	}
	if _, err := controlPayload("unpause", 0, ""); err == nil {
		t.Error("unknown command accepted")
	}
}

// espdns version says the version linked in (internal/version), and takes no arguments.
func TestVersionCommand(t *testing.T) {
	defer func(v string) { version.Version = v }(version.Version)
	version.Version = "0.0.7"
	var b bytes.Buffer
	if err := cmdVersion(&b, nil); err != nil || b.String() != "0.0.7\n" {
		t.Errorf("%q %v", b.String(), err)
	}
	if err := cmdVersion(&b, []string{"x"}); err == nil {
		t.Error("an argument taken")
	}
}

// identify signs for a node not adopted yet too (an LED flickers, nothing more); every other
// control command for a pinned node alone. All sign with the data directory's record.
func TestControlPusher(t *testing.T) {
	_, p := testKeyPEM(t)
	keyFile := filepath.Join(t.TempDir(), "release.pem")
	if err := os.WriteFile(keyFile, p, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"identify", "pause", "flush", "revert"} {
		pu, err := controlPusher(cmd, keyFile, false, t.TempDir())
		if err != nil || pu.Pins == nil || pu.Unadopted != (cmd == "identify") {
			t.Errorf("%s: %+v %v", cmd, pu, err)
		}
	}
}
