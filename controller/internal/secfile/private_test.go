//go:build unix

package secfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// withUmask runs the test under umask m (a process's, so these tests aren't parallel).
func withUmask(t *testing.T, m int) {
	old := syscall.Umask(m)
	t.Cleanup(func() { syscall.Umask(old) })
}

func perm(t *testing.T, p string) fs.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The modes are exact whatever the umask: an open one (000) doesn't open them up, and an odd
// one (0277) doesn't take the owner's write away.
func TestPrivateModesWhateverTheUmask(t *testing.T) {
	for _, m := range []int{0o000, 0o022, 0o277} {
		root := t.TempDir() // before the umask: the test's own directory
		withUmask(t, m)
		dir := filepath.Join(root, "a", "b")
		if err := MkdirAll(dir); err != nil {
			t.Fatalf("umask %04o: %v", m, err)
		}
		for _, d := range []string{filepath.Join(root, "a"), dir} {
			if got := perm(t, d); got != DirMode {
				t.Errorf("umask %04o: %s: %04o, want 0700", m, d, got)
			}
		}
		f := filepath.Join(dir, "log")
		if err := WriteFile(f, []byte("x")); err != nil {
			t.Fatalf("umask %04o: %v", m, err)
		}
		if got := perm(t, f); got != FileMode {
			t.Errorf("umask %04o: file %04o, want 0600", m, got)
		}
		if err := Write(filepath.Join(root, "keys", "k"), []byte("k")); err != nil {
			t.Fatal(err)
		}
		if got := perm(t, filepath.Join(root, "keys")); got != DirMode {
			t.Errorf("umask %04o: Write's directory %04o, want 0700", m, got)
		}
		syscall.Umask(0o022)
	}
}

// A directory already there is left as it is (Tighten's job); a file there is made 0600.
func TestMkdirAllAndOpenFileExisting(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(root); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, root); got != 0o755 {
		t.Errorf("existing directory changed: %04o", got)
	}
	f := filepath.Join(root, "fleet.lock")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := OpenFile(f, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
	if got := perm(t, f); got != FileMode {
		t.Errorf("existing file: %04o, want 0600", got)
	}
	if err := MkdirAll(f); err == nil {
		t.Error("MkdirAll over a file: no error")
	}
	// Not through a link
	l := filepath.Join(root, "link")
	if err := os.Symlink(f, l); err != nil {
		t.Fatal(err)
	}
	if h, err := OpenFile(l, os.O_RDWR); err == nil {
		h.Close()
		t.Error("OpenFile followed a link")
	}
}

// Tighten: a data directory from before (0755, files 0644) becomes 0700/0600; a link and
// its target outside are left as they are; what is already closed is left alone.
func TestTighten(t *testing.T) {
	withUmask(t, 0o022)
	root := filepath.Join(t.TempDir(), "data")
	outside := filepath.Join(t.TempDir(), "outside")
	for _, d := range []string{root, filepath.Join(root, "log"), filepath.Join(root, "firmware", "images")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]fs.FileMode{
		"settings.json":          0o644,
		"fleet.lock":             0o644,
		"log/actions.jsonl":      0o644,
		"firmware/images/c3.bin": 0o664,
		"auth.json":              0o600,
		"readonly.txt":           0o400,
	}
	for name, m := range files {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(name), m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o666); err != nil {
		t.Fatal(err)
	}

	changed, err := Tighten(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{root, filepath.Join(root, "log"), filepath.Join(root, "firmware"), filepath.Join(root, "firmware", "images")} {
		if got := perm(t, d); got != DirMode {
			t.Errorf("%s: %04o, want 0700", d, got)
		}
	}
	for name, m := range files {
		want := FileMode
		if m&0o077 == 0 {
			want = m // already closed: left as it was
		}
		if got := perm(t, filepath.Join(root, name)); got != want {
			t.Errorf("%s: %04o, want %04o", name, got, want)
		}
	}
	if got := perm(t, outside); got != 0o644 {
		t.Errorf("a link's target changed: %04o", got)
	}
	if got := perm(t, filepath.Join(root, "fifo")); got&0o077 == 0 {
		t.Errorf("a FIFO changed: %04o", got)
	}
	want := []string{root, filepath.Join(root, "firmware"), filepath.Join(root, "firmware", "images"),
		filepath.Join(root, "firmware", "images", "c3.bin"), filepath.Join(root, "fleet.lock"),
		filepath.Join(root, "log"), filepath.Join(root, "log", "actions.jsonl"), filepath.Join(root, "settings.json")}
	if !slices.Equal(changed, want) {
		t.Errorf("changed:\n%v\nwant\n%v", changed, want)
	}
	// Again: nothing to change
	if changed, err := Tighten(root); err != nil || len(changed) != 0 {
		t.Errorf("again: %v %v", changed, err)
	}
	// A missing directory is an error to report, not a panic
	if _, err := Tighten(filepath.Join(root, "missing")); err == nil {
		t.Error("missing root: no error")
	}
}

// WriteFile replaces what was there, a longer file's tail too; a file it can't make 0600
// (another user's: as root only, which can chown) is an error and left whole, not emptied.
func TestWriteFileTruncatesOnlyWhenPrivate(t *testing.T) {
	f := filepath.Join(t.TempDir(), "job.json")
	if err := WriteFile(f, []byte("a longer first version")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(f, []byte("short")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(f); err != nil || string(b) != "short" {
		t.Fatalf("rewritten: %q %v", b, err)
	}
	if os.Geteuid() != 0 {
		t.Skip("another user's file: needs root to make")
	}
	if err := os.Chmod(f, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(f, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	// As another user than the file's: drop to a uid that isn't its owner nor root
	if err := syscall.Setreuid(-1, 65533); err != nil {
		t.Skip(err)
	}
	defer syscall.Setreuid(-1, 0)
	if err := WriteFile(f, []byte("x")); err == nil {
		t.Error("another user's file 0666: no error")
	}
	syscall.Setreuid(-1, 0)
	if b, _ := os.ReadFile(f); string(b) != "short" {
		t.Errorf("another user's file changed: %q", b)
	}
}

// A data directory given by a link: the link's target is the data directory, tightened.
func TestTightenRootLink(t *testing.T) {
	withUmask(t, 0o022)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "settings.json"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "data")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	changed, err := Tighten(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 {
		t.Errorf("changed %q, want the directory, log and settings.json", changed)
	}
	for p, want := range map[string]fs.FileMode{real: DirMode, filepath.Join(real, "log"): DirMode, filepath.Join(real, "settings.json"): FileMode} {
		if got := perm(t, p); got != want {
			t.Errorf("%s: %04o, want %04o", p, got, want)
		}
	}
}
