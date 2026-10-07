package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/release"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// keyNode is a node that trusts these key fingerprints (slot 0, slot 1).
func keyNode(t *testing.T, trusted ...string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			json.NewEncoder(w).Encode(map[string]any{"node_id": "aa:bb:cc:dd:ee:ff", "keys": trusted})
		case "/health":
			json.NewEncoder(w).Encode(map[string]any{"state": "healthy", "answering": true})
		default:
			if r.Method != http.MethodGet {
				t.Errorf("key import sent the node %s %s", r.Method, r.URL.Path)
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// stdin replaces standard input with text for the test.
func stdin(t *testing.T, text string) {
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(text)
	f.Seek(0, 0)
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old; f.Close() })
}

// espdns key import: from standard input (base64 of the PEM), written 0600 only
// when a node trusts it; the same key again changes nothing; a different one, or the
// recovery key, is refused.
func TestKeyImport(t *testing.T) {
	k, p := testKeyPEM(t)
	rec, _ := testKeyPEM(t)
	fp := release.Fingerprint(release.PublicRaw(k))
	recFP := release.Fingerprint(release.PublicRaw(rec))
	dir := t.TempDir()
	node := keyNode(t, fp, recFP)
	if err := settings.Save(settings.Path(dir), settings.Settings{Nodes: []string{node}}); err != nil {
		t.Fatal(err)
	}
	// The recovery public key is a must for an import.
	recPub := filepath.Join(t.TempDir(), "recovery.pub")
	os.WriteFile(recPub, release.PublicRaw(rec), 0o644)
	stdin(t, base64.StdEncoding.EncodeToString(p)+"\n")
	if err := cmdKey([]string{"import", "-data", dir}); err == nil || !strings.Contains(err.Error(), "-recovery-pub") {
		t.Fatalf("an import without -recovery-pub: %v", err)
	}
	if _, err := os.Stat(keys.Path(dir)); err == nil {
		t.Fatal("imported without -recovery-pub")
	}
	stdin(t, base64.StdEncoding.EncodeToString(p)+"\n")
	if err := cmdKey([]string{"import", "-data", dir, "-mdns", "0", "-recovery-pub", recPub}); err != nil {
		t.Fatal(err)
	}
	got, err := keys.FileSource{Path: keys.Path(dir)}.Key()
	if err != nil || !got.Equal(k) {
		t.Fatalf("imported key: %v", err)
	}
	if err := cmdKey([]string{"status", "-data", dir, "-mdns", "0"}); err != nil {
		t.Fatalf("status: %v", err)
	}
	stdin(t, string(p))
	if err := cmdKey([]string{"import", "-data", dir, "-recovery-pub", recPub}); err != nil {
		t.Fatalf("the same key again: %v", err)
	}

	// A key no node trusts.
	other, op := testKeyPEM(t)
	_ = other
	stdin(t, string(op))
	if err := cmdKey([]string{"import", "-data", dir, "-recovery-pub", recPub}); err == nil || !strings.Contains(err.Error(), "no node in settings.json trusts it") {
		t.Fatalf("untrusted key: %v", err)
	}
	// The recovery key: by its public key file, and by the node's slot 1.
	rp, _ := keys.Encode(rec)
	stdin(t, string(rp))
	if err := cmdKey([]string{"import", "-data", dir, "-recovery-pub", recPub}); err == nil || !strings.Contains(err.Error(), "recovery key") {
		t.Fatalf("recovery key: %v", err)
	}
	otherRec := filepath.Join(t.TempDir(), "other.pub")
	os.WriteFile(otherRec, release.PublicRaw(other), 0o644)
	stdin(t, string(rp))
	if err := cmdKey([]string{"import", "-data", dir, "-recovery-pub", otherRec, "-replace"}); err == nil || !strings.Contains(err.Error(), "slot 1") {
		t.Fatalf("recovery key by slot 1: %v", err)
	}
	// Trusted by the firmware's public key file, a different key than the one imported:
	// refused without -replace.
	pub := filepath.Join(t.TempDir(), "release.pub")
	os.WriteFile(pub, release.PublicRaw(other), 0o644)
	stdin(t, string(op))
	if err := cmdKey([]string{"import", "-data", dir, "-recovery-pub", recPub, "-pub", pub}); err == nil || !strings.Contains(err.Error(), "-replace") {
		t.Fatalf("a different key: %v", err)
	}
	if got, _ := (keys.FileSource{Path: keys.Path(dir)}).Key(); !got.Equal(k) {
		t.Fatal("replaced")
	}
	// A key file opened up: status refuses it.
	os.Chmod(keys.Path(dir), 0o644)
	if err := cmdKey([]string{"status", "-data", dir, "-mdns", "0"}); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("status of a 0644 key: %v", err)
	}
}

func TestPasswd(t *testing.T) {
	dir := t.TempDir()
	auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1}
	stdin(t, "short\n")
	if err := cmdPasswd([]string{"-data", dir}); err == nil {
		t.Fatal("a short password set")
	}
	stdin(t, "a long enough password\n")
	if err := cmdPasswd([]string{"-data", dir}); err != nil {
		t.Fatal(err)
	}
	c, err := auth.Load(auth.Path(dir))
	if err != nil || c.User != auth.DefaultUser {
		t.Fatalf("%+v %v", c, err)
	}
	if ok, _ := auth.Verify(c.Hash, "a long enough password"); !ok {
		t.Fatal("the password set isn't the one given")
	}
	// Again, without -user: the user set before stays.
	stdin(t, "a second long password\n")
	if err := cmdPasswd([]string{"-data", dir, "-user", "alice"}); err != nil {
		t.Fatal(err)
	}
	stdin(t, "a third long password\n")
	if err := cmdPasswd([]string{"-data", dir}); err != nil {
		t.Fatal(err)
	}
	if c, _ := auth.Load(auth.Path(dir)); c.User != "alice" {
		t.Fatalf("user %q", c.User)
	}
}
