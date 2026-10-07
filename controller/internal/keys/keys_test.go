package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skitzo2000/espdns/controller/internal/release"
)

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, b
}

func TestParse(t *testing.T) {
	k, p := newKey(t)
	b64 := base64.StdEncoding.EncodeToString(p)
	wrapped := b64[:40] + "\n" + b64[40:] + "\n"
	for name, v := range map[string]string{"PEM": string(p), "base64": b64, "base64, wrapped": wrapped, "PEM, padded": "\n " + string(p) + "\n"} {
		got, err := Parse("in", []byte(v))
		if err != nil || !got.Equal(k) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, v := range map[string]string{"empty": " \n", "garbage": "secret-ish value", "base64 of garbage": base64.StdEncoding.EncodeToString([]byte("secret-ish value"))} {
		_, err := Parse("in", []byte(v))
		if err == nil || strings.Contains(err.Error(), "secret-ish") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	src := FileSource{Path: Path(dir)}
	if _, err := src.Key(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no file: %v", err)
	}
	k, _ := newKey(t)
	if same, err := Import(src.Path, k, false); same || err != nil {
		t.Fatalf("import: %v %v", same, err)
	}
	fi, _ := os.Stat(src.Path)
	di, _ := os.Stat(filepath.Dir(src.Path))
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes: file %v, dir %v", fi.Mode(), di.Mode())
	}
	if got, err := src.Key(); err != nil || !got.Equal(k) {
		t.Fatalf("read back: %v", err)
	}
	// Opened to the group or others: refused, not used.
	for _, m := range []os.FileMode{0o640, 0o604, 0o660} {
		os.Chmod(src.Path, m)
		if _, err := src.Key(); err == nil || errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %v: %v", m, err)
		}
	}
	os.Chmod(src.Path, 0o600)
	// A link to a key elsewhere: refused.
	link := filepath.Join(dir, "link.pem")
	os.Symlink(src.Path, link)
	if _, err := (FileSource{Path: link}).Key(); err == nil {
		t.Error("a symbolic link used")
	}
}

func TestImport(t *testing.T) {
	path := Path(t.TempDir())
	k, _ := newKey(t)
	k2, _ := newKey(t)
	if _, err := Import(path, k, false); err != nil {
		t.Fatal(err)
	}
	if same, err := Import(path, k, false); !same || err != nil {
		t.Fatalf("the same key again: %v %v", same, err)
	}
	if _, err := Import(path, k2, false); !errors.Is(err, ErrExists) {
		t.Fatalf("a different key: %v", err)
	}
	if got, _ := (FileSource{path}).Key(); !got.Equal(k) {
		t.Fatal("the refused import replaced the key")
	}
	if _, err := Import(path, k2, true); err != nil {
		t.Fatalf("-replace: %v", err)
	}
	if got, _ := (FileSource{path}).Key(); !got.Equal(k2) {
		t.Fatal("not replaced")
	}
	// A key file that can't be used isn't silently replaced either.
	os.Chmod(path, 0o644)
	if _, err := Import(path, k, false); err == nil {
		t.Fatal("replaced an unreadable key without -replace")
	}
	// No temporary files left behind.
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Fatalf("files in keys/: %v", ents)
	}
}

func TestTrust(t *testing.T) {
	k, _ := newKey(t)
	other, _ := newKey(t)
	rec, _ := newKey(t)
	fp := func(k *ecdsa.PrivateKey) string { return release.Fingerprint(release.PublicRaw(k)) }
	pub, otherPub, recPub := release.PublicRaw(k), release.PublicRaw(other), release.PublicRaw(rec)
	trusting := NodeKeys{Addr: "a", Keys: []string{fp(k), fp(rec)}, Listed: true}
	elsewhere := NodeKeys{Addr: "b", Keys: []string{fp(other), fp(rec)}, Listed: true}
	down := NodeKeys{Addr: "c", Error: "connection refused", Listed: true}
	// A host found only over mDNS, listing whatever key it likes in slot 0.
	mdnsOnly := NodeKeys{Addr: "m", Keys: []string{fp(k), fp(other)}}
	mdnsRec := NodeKeys{Addr: "m", Keys: []string{fp(rec), fp(other)}}

	cases := []struct {
		name    string
		key     *ecdsa.PrivateKey
		pub     []byte
		recPub  []byte
		nodes   []NodeKeys
		ok      bool
		errHas  string
		trusted []string
	}{
		{"the firmware's key, no node reached", k, pub, recPub, []NodeKeys{down}, true, "", nil},
		{"a node trusts it", k, nil, recPub, []NodeKeys{trusting, elsewhere}, true, "", []string{"a"}},
		{"a node trusts it, not the pub file's", k, otherPub, recPub, []NodeKeys{trusting}, true, "", []string{"a"}},
		{"nothing trusts it", k, otherPub, recPub, []NodeKeys{elsewhere, down}, false, "no node in settings.json trusts it", nil},
		{"no nodes, no pub", k, nil, recPub, nil, false, "no node in settings.json was asked", nil},
		{"only an mDNS host trusts it", k, otherPub, recPub, []NodeKeys{mdnsOnly, elsewhere}, false, "no node in settings.json trusts it", nil},
		{"the recovery key, an mDNS host vouching", rec, nil, nil, []NodeKeys{mdnsRec}, false, "no node in settings.json was asked", nil},
		{"the recovery key, by a node's slot 1", rec, nil, nil, []NodeKeys{trusting}, false, "recovery key", nil},
		{"the recovery key, by an mDNS host's slot 1", rec, nil, nil, []NodeKeys{{Addr: "m", Keys: []string{fp(other), fp(rec)}}}, false, "recovery key", nil},
		{"the recovery key, by its pub file", rec, recPub, recPub, nil, false, "recovery key", nil},
	}
	for _, c := range cases {
		r, err := Trust(c.key, "release.pub", c.pub, c.recPub, c.nodes)
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), c.errHas) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if strings.Join(r.Trusting, ",") != strings.Join(c.trusted, ",") {
			t.Errorf("%s: trusting %v", c.name, r.Trusting)
		}
	}
	r, _ := Trust(k, "release.pub", pub, nil, []NodeKeys{trusting, elsewhere, down, mdnsOnly})
	text := strings.Join(r.Lines(), "\n")
	for _, want := range []string{fp(k), "trusted by a", "NOT trusted by b", "not read: c", "m, found over mDNS only: not counted"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if _, err := Trust(k, "release.pub", []byte("short"), nil, nil); err == nil {
		t.Error("a pub file of the wrong size taken")
	}
}
