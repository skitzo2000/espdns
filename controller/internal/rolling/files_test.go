package rolling

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func list(t *testing.T, name string) []byte {
	t.Helper()
	b, _, err := blocklist.Build(blocklist.Compile([]blocklist.Entry{{Name: name}}), blocklist.BuildOptions{Bits: 44, XorBits: 8, Keys: 1})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A request with Files is fingerprinted and built from the same bytes: a file replaced
// after the fingerprint (the dry run's check) is not what is pushed, and a new request
// (the next dry run) sees the new file.
func TestFilesFingerprintIsWhatIsPushed(t *testing.T) {
	data := t.TempDir()
	if err := settings.Save(settings.Path(data), settings.Settings{Nodes: []string{"198.51.100.1"}}); err != nil {
		t.Fatal(err)
	}
	old, repl := list(t, "ads.example.net"), list(t, "other.example.net")
	write(t, filepath.Join(data, ListsDir, "l.bin"), old)
	w := Web{Kind: "blocklist", Nodes: []string{"198.51.100.1"}, File: "l.bin"}
	secret := []byte("k")
	r, err := w.Request(data, "")
	if err != nil {
		t.Fatal(err)
	}
	fp := r.Fingerprint(secret)
	// Replaced, the settings too, between the check and the build.
	write(t, filepath.Join(data, ListsDir, "l.bin"), repl)
	if err := settings.Save(settings.Path(data), settings.Settings{Nodes: []string{"198.51.100.1"}, DNSPeers: []string{"198.51.100.9"}}); err != nil {
		t.Fatal(err)
	}
	ch, _, err := LoadChange(r, r.Hosts, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ch.Payload(context.Background(), "198.51.100.1", release.NodeStatus{})
	if err != nil || !bytes.Equal(got, old) {
		t.Fatalf("pushed %d bytes (want the %d read first), %v", len(got), len(old), err)
	}
	if peers, err := DNSPeers(r, t.Logf); err != nil || len(peers) != 0 {
		t.Fatalf("the settings read again: %v, %v", peers, err)
	}
	if r.Fingerprint(secret) != fp {
		t.Fatal("the fingerprint changed with the request's own reads")
	}
	r2, err := w.Request(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Fingerprint(secret) == fp {
		t.Fatal("a new request doesn't see the replaced file")
	}
}
