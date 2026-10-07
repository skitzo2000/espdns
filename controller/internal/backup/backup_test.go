package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/keys"
)

const pass = "a backup passphrase"

func init() {
	WorkFactor = 10
	auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1}
}

func write(t *testing.T, dir, rel string, b []byte, mode fs.FileMode) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// dataDir is a data directory as the controller keeps one.
func dataDir(t *testing.T) string {
	dir := t.TempDir()
	write(t, dir, "settings.json", []byte(`{"nodes": ["192.0.2.253"], "dns_peers": ["192.0.2.254"]}`+"\n"), 0o644)
	if err := auth.SetPassword(auth.Path(dir), "admin", "a long enough password"); err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := keys.Import(keys.Path(dir), k, false); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.ImportToken(keys.TokenPath(dir), "0123456789abcdef", false); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "configs/dns2.json", []byte(`{"name": "dns2"}`), 0o600)
	write(t, dir, "configs/.history/dns2.json.20261003-120000", []byte(`{"name": "dns2", "old": 1}`), 0o600)
	write(t, dir, "configs/.pushed/02:00:00:00:00:11.json", []byte(`{"seq": 1}`), 0o600)
	write(t, dir, "configs/.tmp-123", []byte("half a save"), 0o600)
	write(t, dir, "zones/home.example.zone", []byte("$ORIGIN home.example.\n"), 0o600)
	write(t, dir, "lists/list.bin", bytes.Repeat([]byte{1, 2, 3}, 100_000), 0o644)
	write(t, dir, "boards/mine.json", []byte(`{"name": "mine"}`), 0o644)
	write(t, dir, "log/actions.jsonl", []byte(`{"event":"start"}`+"\n"), 0o644)
	write(t, dir, "log/jobs/20261003-120000-abcd.json", []byte(`{}`), 0o644)
	write(t, dir, "firmware/builds/p4-ip101/dns2.bin", []byte("an app"), 0o644)
	write(t, dir, "fleet.lock", nil, 0o644)
	if err := os.Symlink("list.bin", filepath.Join(dir, "lists/link.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "empty"), 0o750); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	os.Chtimes(filepath.Join(dir, "zones/home.example.zone"), old, old)
	return dir
}

func backup(t *testing.T, dir string, o Options, rs ...age.Recipient) ([]byte, Summary) {
	t.Helper()
	if len(rs) == 0 {
		r, _, err := Passphrase(pass)
		if err != nil {
			t.Fatal(err)
		}
		rs = []age.Recipient{r}
	}
	var b bytes.Buffer
	s, err := Write(dir, &b, rs, o)
	if err != nil {
		t.Fatal(err)
	}
	return b.Bytes(), s
}

func ids(t *testing.T, p string) []age.Identity {
	_, id, err := Passphrase(p)
	if err != nil {
		t.Fatal(err)
	}
	return []age.Identity{id}
}

type node struct {
	mode fs.FileMode
	mod  time.Time
	data string
}

// tree is every entry under dir by path, with its mode, time and contents.
func tree(t *testing.T, dir string) map[string]node {
	out := map[string]node{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		fi, _ := os.Lstat(p)
		n := node{mode: fi.Mode(), mod: fi.ModTime()}
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			n.data = string(b)
		}
		if d.IsDir() {
			n.mod = time.Time{} // a directory's time changes as entries go in; files' are what matter
		}
		out[filepath.ToSlash(rel)] = n
		return nil
	})
	return out
}

func TestRoundTrip(t *testing.T) {
	src := dataDir(t)
	b, s := backup(t, src, Options{})
	if s.Files != 12 || len(s.Skipped) != 1 || !strings.Contains(s.Skipped[0], "lists/link.bin: a symbolic link") {
		t.Errorf("summary %+v", s)
	}
	dst := filepath.Join(t.TempDir(), "data")
	c, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want, got := tree(t, src), tree(t, dst)
	for _, gone := range []string{"firmware", "firmware/builds", "firmware/builds/p4-ip101", "firmware/builds/p4-ip101/dns2.bin",
		"configs/.tmp-123", "lists/link.bin"} {
		delete(want, gone)
	}
	delete(want, "fleet.lock") // each its own: the restore takes the new directory's
	delete(got, "fleet.lock")
	for rel, w := range want {
		// The mode is the controller user's only, whatever the source's (0755 and 0644 there)
		w.mode = w.mode.Type() | mode(w.mode.IsDir())
		if g, ok := got[rel]; !ok || g.mode != w.mode || g.data != w.data || !g.mod.Equal(w.mod) {
			t.Errorf("%s: got %v %v (%d bytes), want %v %v (%d bytes)", rel, g.mode, g.mod, len(g.data), w.mode, w.mod, len(w.data))
		}
	}
	for rel := range got {
		if _, ok := want[rel]; !ok {
			t.Errorf("%s: restored, not in the data directory", rel)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dst, "keys")); fi.Mode().Perm() != 0o700 {
		t.Errorf("keys/ %v", fi.Mode())
	}
	if len(c.Checked) != 4 || !strings.Contains(strings.Join(c.Checked, "\n"), "fingerprint") {
		t.Errorf("checked %v", c.Checked)
	}
	// The firmware too, when asked.
	b, s = backup(t, src, Options{Firmware: true})
	if s.Files != 13 {
		t.Errorf("with firmware: %+v", s)
	}
	dst2 := filepath.Join(t.TempDir(), "data")
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), dst2, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst2, "firmware/builds/p4-ip101/dns2.bin")); string(got) != "an app" {
		t.Errorf("firmware %q", got)
	}
}

// An age public key instead of a passphrase.
func TestRecipient(t *testing.T) {
	src := dataDir(t)
	id, _ := age.GenerateX25519Identity()
	b, _ := backup(t, src, Options{}, id.Recipient())
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), t.TempDir(), RestoreOptions{DryRun: true}); !errors.Is(err, ErrWrongKey) {
		t.Errorf("a passphrase for a key's backup: %v", err)
	}
	if _, err := Restore(bytes.NewReader(b), []age.Identity{id}, filepath.Join(t.TempDir(), "d"), RestoreOptions{}); err != nil {
		t.Error(err)
	}
}

// nothingRestored checks dst holds nothing a refused restore left: no file, no stage.
func nothingRestored(t *testing.T, dst string) {
	t.Helper()
	ents, _ := os.ReadDir(dst)
	for _, e := range ents {
		if e.Name() != fleetlock.File {
			t.Errorf("left in %s: %s", dst, e.Name())
		}
	}
}

func TestWrongPassphraseTamperedTruncated(t *testing.T) {
	b, _ := backup(t, dataDir(t), Options{})
	dst := t.TempDir()
	if _, err := Restore(bytes.NewReader(b), ids(t, "another passphrase"), dst, RestoreOptions{}); !errors.Is(err, ErrWrongKey) {
		t.Errorf("wrong passphrase: %v", err)
	}
	nothingRestored(t, dst)
	// A byte changed anywhere after the header: the payload's authentication fails.
	hdr := bytes.Index(b, []byte("\n---")) + 50
	for _, at := range []int{hdr, hdr + 1000, len(b) / 2, len(b) - 20} {
		bad := bytes.Clone(b)
		bad[at] ^= 0x40
		_, err := Restore(bytes.NewReader(bad), ids(t, pass), dst, RestoreOptions{})
		if !errors.Is(err, ErrDamaged) {
			t.Errorf("byte %d of %d changed: %v", at, len(b), err)
		}
		nothingRestored(t, dst)
	}
	// Cut short anywhere, at a chunk's end too (age's chunks are 64 KiB and 16 bytes).
	for _, n := range []int{0, 20, hdr - 40, hdr + 10, 65536 + 16 + hdr, len(b) / 2, len(b) - 17, len(b) - 1} {
		if n < 0 || n >= len(b) {
			continue
		}
		_, err := Restore(bytes.NewReader(b[:n]), ids(t, pass), dst, RestoreOptions{})
		if err == nil {
			t.Errorf("cut to %d of %d: restored", n, len(b))
		}
		nothingRestored(t, dst)
	}
	// Not a backup at all.
	if _, err := Restore(strings.NewReader("hello"), ids(t, pass), dst, RestoreOptions{}); err == nil || !strings.Contains(err.Error(), "age file") {
		t.Errorf("not age: %v", err)
	}
}

func TestNotEmptyAndForce(t *testing.T) {
	b, _ := backup(t, dataDir(t), Options{})
	dst := t.TempDir()
	write(t, dst, "settings.json", []byte(`{}`), 0o644)
	write(t, dst, "configs/mine.json", []byte(`{"name": "mine"}`), 0o600)
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{}); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("non-empty: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "settings.json")); string(got) != "{}" {
		t.Errorf("touched: %q", got)
	}
	// A dry run reads it all and writes nothing, there or anywhere.
	c, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{DryRun: true})
	if err != nil || len(c.Entries) == 0 || c.Manifest.Format != Format {
		t.Fatalf("dry run: %v %+v", err, c.Manifest)
	}
	missing := filepath.Join(t.TempDir(), "none")
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), missing, RestoreOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a dry run made %s", missing)
	}
	// Forced: what was there is moved aside, nothing deleted.
	c, err = Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{Force: true,
		Now: func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	if c.MovedAside != filepath.Join(dst, ".before-restore-20261003-120000") {
		t.Errorf("moved aside to %q", c.MovedAside)
	}
	if got, _ := os.ReadFile(filepath.Join(c.MovedAside, "configs/mine.json")); string(got) != `{"name": "mine"}` {
		t.Errorf("aside: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "configs/dns2.json")); string(got) != `{"name": "dns2"}` {
		t.Errorf("restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dst, "configs/mine.json")); err == nil {
		t.Error("the old config is still in place")
	}
	// A directory with only a fleet lock is empty.
	only := t.TempDir()
	write(t, only, "fleet.lock", nil, 0o644)
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), only, RestoreOptions{}); err != nil {
		t.Error(err)
	}
}

// entry is one tar entry of a crafted backup.
type entry struct {
	h    tar.Header
	data string
}

func file(name, data string) entry {
	return entry{h: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(data))}, data: data}
}

func dir(name string) entry {
	return entry{h: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: 0o755}}
}

// craft is a backup of entries, encrypted to pass: the manifest given (nil: a good one),
// then the entries, then an end that matches them (unless end is given).
func craft(t *testing.T, m *Manifest, entries []entry, end *End) []byte {
	if m == nil {
		m = &Manifest{Kind: Kind, Format: Format, Created: time.Now()}
	}
	r, _, _ := Passphrase(pass)
	var b bytes.Buffer
	aw, _ := age.Encrypt(&b, r)
	tw := tar.NewWriter(aw)
	// Errors are ignored: an entry over MaxFile is only its header, and the stream ends there.
	add := func(h tar.Header, data string) {
		if tw.WriteHeader(&h) == nil {
			io.WriteString(tw, data)
		}
	}
	mb, _ := json.Marshal(m)
	add(tar.Header{Typeflag: tar.TypeReg, Name: ManifestName, Mode: 0o600, Size: int64(len(mb))}, string(mb))
	e := End{Files: map[string]FileSum{}}
	for _, en := range entries {
		add(en.h, en.data)
		if en.h.Typeflag == tar.TypeReg {
			s := sha256.Sum256([]byte(en.data))
			e.Files[strings.TrimPrefix(en.h.Name, DataPrefix)] = FileSum{Size: int64(len(en.data)), SHA256: hex.EncodeToString(s[:])}
		}
	}
	if end == nil {
		end = &e
	}
	eb, _ := json.Marshal(end)
	add(tar.Header{Typeflag: tar.TypeReg, Name: EndName, Mode: 0o600, Size: int64(len(eb))}, string(eb))
	tw.Close()
	aw.Close()
	return b.Bytes()
}

func TestCraftedRefused(t *testing.T) {
	good := []entry{dir("data/configs/"), file("data/configs/a.json", "{}")}
	cases := map[string]struct {
		m       *Manifest
		entries []entry
		end     *End
		want    error
		text    string
	}{
		"traversal":         {entries: []entry{file("data/../escaped", "x")}, want: ErrRefused},
		"deep traversal":    {entries: []entry{dir("data/configs/"), file("data/configs/../../escaped", "x")}, want: ErrRefused},
		"absolute":          {entries: []entry{file("/tmp/escaped", "x")}, want: ErrRefused},
		"absolute in data":  {entries: []entry{file("data//tmp/escaped", "x")}, want: ErrRefused},
		"outside data/":     {entries: []entry{file("escaped", "x")}, want: ErrRefused},
		"backslash":         {entries: []entry{file(`data/..\escaped`, "x")}, want: ErrRefused},
		"dot":               {entries: []entry{dir("data/configs/"), file("data/configs/./a.json", "x")}, want: ErrRefused},
		"control character": {entries: []entry{file("data/a\nb", "x")}, want: ErrRefused},
		"symlink": {entries: []entry{dir("data/keys/"), {h: tar.Header{Typeflag: tar.TypeSymlink, Name: "data/keys/release.pem",
			Linkname: "/etc/shadow"}}}, want: ErrRefused, text: "symbolic link"},
		"hard link": {entries: []entry{{h: tar.Header{Typeflag: tar.TypeLink, Name: "data/settings.json",
			Linkname: "/etc/passwd"}}}, want: ErrRefused, text: "hard link"},
		"device": {entries: []entry{{h: tar.Header{Typeflag: tar.TypeChar, Name: "data/null", Devmajor: 1, Devminor: 3}}},
			want: ErrRefused, text: "device"},
		"fifo":            {entries: []entry{{h: tar.Header{Typeflag: tar.TypeFifo, Name: "data/p"}}}, want: ErrRefused},
		"file before dir": {entries: []entry{file("data/configs/a.json", "{}")}, want: ErrRefused},
		"twice":           {entries: append(good, file("data/configs/a.json", "{}")), want: ErrRefused},
		"fleet lock":      {entries: []entry{file("data/fleet.lock", "")}, want: ErrRefused},
		"hidden top":      {entries: []entry{dir("data/.restore-x/")}, want: ErrRefused},
		"too big": {entries: []entry{{h: tar.Header{Typeflag: tar.TypeReg, Name: "data/big", Size: MaxFile + 1}}},
			want: ErrRefused},
		"newer format":    {m: &Manifest{Kind: Kind, Format: Format + 1}, entries: good, want: ErrNewer},
		"another kind":    {m: &Manifest{Kind: "tarball", Format: 1}, entries: good, text: "not an espdns backup"},
		"sum differs":     {entries: good, end: &End{Files: map[string]FileSum{"configs/a.json": {Size: 2, SHA256: "00"}}}, want: ErrDamaged},
		"file not in end": {entries: good, end: &End{Files: map[string]FileSum{}}, want: ErrDamaged},
		"bad settings": {entries: []entry{file("data/settings.json", `{"nodes": ["not an address"]}`)},
			text: "settings.json can't be used"},
		"bad key":   {entries: []entry{dir("data/keys/"), file("data/keys/release.pem", "not a key")}, text: "keys/release.pem can't be used"},
		"bad login": {entries: []entry{file("data/auth.json", `{"user": "admin", "hash": "plain"}`)}, text: "auth.json can't be used"},
	}
	outside := t.TempDir()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			b := craft(t, c.m, c.entries, c.end)
			// The data directory is two levels down, so "../escaped" from data/ would land in base.
			base := t.TempDir()
			dst := filepath.Join(base, "a", "data")
			_, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{})
			if err == nil || c.want != nil && !errors.Is(err, c.want) || c.text != "" && !strings.Contains(err.Error(), c.text) {
				t.Fatalf("got %v, want %v %q", err, c.want, c.text)
			}
			nothingRestored(t, dst)
			for _, d := range []string{base, filepath.Join(base, "a"), outside, "/tmp"} {
				if _, err := os.Lstat(filepath.Join(d, "escaped")); err == nil {
					t.Fatalf("written to %s", d)
				}
			}
		})
	}
	// Nothing after the end, and the end must be there.
	b := craft(t, nil, good, nil)
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), filepath.Join(t.TempDir(), "d"), RestoreOptions{}); err != nil {
		t.Fatalf("the good one: %v", err)
	}
}

// Every restored entry is the controller user's only, whatever the backup says: directories
// 0700, files 0600, no set-id or execute bits.
func TestRestoredModes(t *testing.T) {
	b := craft(t, nil, []entry{dir("data/keys/"), file("data/keys/primary.token", "0123456789abcdef"), dir("data/lists/"), file("data/lists/a.bin", "x"),
		{h: tar.Header{Typeflag: tar.TypeReg, Name: "data/run.sh", Mode: 0o4777, Size: 2}, data: "hi"}}, nil)
	dst := filepath.Join(t.TempDir(), "d")
	if _, err := Restore(bytes.NewReader(b), ids(t, pass), dst, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]fs.FileMode{"": fs.ModeDir | 0o700, "keys": fs.ModeDir | 0o700, "keys/primary.token": 0o600, "run.sh": 0o600, "lists": fs.ModeDir | 0o700, "lists/a.bin": 0o600} {
		if fi, err := os.Stat(filepath.Join(dst, rel)); err != nil || fi.Mode() != want {
			t.Errorf("%s: %v, want %v", rel, fi.Mode(), want)
		}
	}
}

// A backup stops when its context is done (the page's request gone, the CLI's Ctrl-C).
func TestWriteStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _, _ := Passphrase(pass)
	if _, err := Write(dataDir(t), io.Discard, []age.Recipient{r}, Options{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// A backup takes the fleet lock: refused at once with no wait, naming who has it; with one,
// it goes ahead once the holder lets go.
func TestLock(t *testing.T) {
	dir := dataDir(t)
	held, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("espdns rollout", "-kind firmware"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(context.Background(), dir, "espdns backup", 0, nil); !errors.Is(err, fleetlock.ErrLocked) ||
		!strings.Contains(err.Error(), "espdns rollout") {
		t.Fatalf("held: %v", err)
	}
	waited := make(chan fleetlock.Holder, 1)
	go func() {
		<-waited
		held.Release()
	}()
	lk, err := Lock(context.Background(), dir, "espdns backup", time.Minute, func(h fleetlock.Holder) { waited <- h })
	if err != nil {
		t.Fatal(err)
	}
	lk.Release()
}
