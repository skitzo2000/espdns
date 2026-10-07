package filestore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testStore(t *testing.T) Store {
	return Store{Dir: filepath.Join(t.TempDir(), "x"), Max: 64, Keep: 3,
		Name: func(n string) error {
			if !strings.HasSuffix(n, ".txt") || strings.ContainsAny(n, "/\\") || strings.HasPrefix(n, ".") {
				return fmt.Errorf("%q: not a name", n)
			}
			return nil
		},
		Check: func(_ string, b []byte) error {
			if strings.Contains(string(b), "bad") {
				return errors.New("bad text")
			}
			return nil
		}}
}

func perm(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// A save: checked, whole, 0600, only over the version it was made from, the one it replaces
// kept (the newest Keep); a delete only of the version named, kept too.
func TestSaveDelete(t *testing.T) {
	s := testStore(t)
	if err := s.Save("a.txt", []byte("bad"), ""); err == nil {
		t.Error("bad text saved")
	}
	if err := s.Save("a.txt", []byte(strings.Repeat("x", 65)), ""); err == nil {
		t.Error("over Max saved")
	}
	if err := s.Save("../a.txt", []byte("v"), ""); err == nil {
		t.Error("a path saved")
	}
	if err := s.Save("a.txt", []byte("v1"), ""); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "a.txt")
	if perm(t, p) != 0o600 {
		t.Errorf("mode %v", perm(t, p))
	}
	if err := s.Save("a.txt", []byte("v1"), ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("new over a file: %v", err)
	}
	if err := s.Save("a.txt", []byte("v2"), Hash([]byte("other"))); !errors.Is(err, ErrChanged) {
		t.Errorf("stale: %v", err)
	}
	for i := 2; i <= 6; i++ {
		prev := []byte(fmt.Sprintf("v%d", i-1))
		if err := s.Save("a.txt", []byte(fmt.Sprintf("v%d", i)), Hash(prev)); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History("a.txt")
	if err != nil || len(h) != 3 {
		t.Fatalf("history %v %v", h, err)
	}
	if b, _ := s.ReadVersion("a.txt", h[0].File); string(b) != "v5" {
		t.Errorf("newest kept %q", b)
	}
	for _, bad := range []string{"../a.txt." + h[0].File[len("a.txt."):], "a.txt", h[0].File + "/x", "b.txt." + h[0].File[len("a.txt."):]} {
		if _, err := s.ReadVersion("a.txt", bad); err == nil {
			t.Errorf("version %q read", bad)
		}
	}
	if err := s.Delete("a.txt", ""); err == nil {
		t.Error("a delete without a hash")
	}
	if err := s.Delete("a.txt", Hash([]byte("v5"))); !errors.Is(err, ErrChanged) {
		t.Errorf("a delete of another version: %v", err)
	}
	if err := s.Delete("a.txt", Hash([]byte("v6"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("still there: %v", err)
	}
	k, err := s.Kept()
	if err != nil || len(k) != 1 {
		t.Fatalf("kept %v %v", k, err)
	}
	if b, _ := s.ReadVersion("a.txt", k["a.txt"].File); string(b) != "v6" {
		t.Errorf("deleted version kept %q", b)
	}
	if err := s.Delete("a.txt", Hash([]byte("v6"))); err == nil {
		t.Error("deleted twice")
	}
	// Saved again: no longer deleted.
	if err := s.Save("a.txt", []byte("v7"), ""); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.Kept(); len(k) != 0 {
		t.Errorf("kept after a save %v", k)
	}
	if n, _ := s.Names(); len(n) != 1 || n[0] != "a.txt" {
		t.Errorf("names %v", n)
	}
	// A symbolic link isn't written through.
	os.WriteFile(filepath.Join(s.Dir, "..", "target.txt"), []byte("t"), 0o600)
	os.Symlink(filepath.Join(s.Dir, "..", "target.txt"), filepath.Join(s.Dir, "l.txt"))
	if err := s.Save("l.txt", []byte("x"), Hash([]byte("t"))); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("through a link: %v", err)
	}
}
