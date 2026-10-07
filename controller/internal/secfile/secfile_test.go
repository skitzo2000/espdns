package secfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "k")
	if _, err := Read(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := Write(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	b, err := Read(path)
	if err != nil || string(b) != "two" {
		t.Fatalf("read: %q %v", b, err)
	}
	fi, _ := os.Stat(path)
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("modes %v %v", fi.Mode(), di.Mode())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}

func TestRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	os.WriteFile(path, []byte("x"), 0o644)
	if _, err := Read(path); err == nil || !strings.Contains(err.Error(), "mode 0644") {
		t.Errorf("0644: %v", err)
	}
	os.Chmod(path, 0o600)
	link := filepath.Join(dir, "l")
	os.Symlink(path, link)
	if _, err := Read(link); err == nil {
		t.Error("a link read")
	}
	if err := Write(link, []byte("y")); err == nil {
		t.Error("wrote through a link")
	}
	os.Mkdir(filepath.Join(dir, "d"), 0o700)
	if _, err := Read(filepath.Join(dir, "d")); err == nil {
		t.Error("a directory read")
	}
	big := filepath.Join(dir, "big")
	os.WriteFile(big, make([]byte, MaxSize+1), 0o600)
	if _, err := Read(big); err == nil {
		t.Error("an oversize file read")
	}
}

// Create: the file whole, 0600, only if nothing is there; of many at once exactly one
// succeeds, the rest get fs.ErrExist and change nothing; no temporary file is left.
func TestCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	path := filepath.Join(dir, "f")
	if err := Create(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, []byte("two")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("over a file: %v", err)
	}
	if b, err := Read(path); err != nil || string(b) != "one" {
		t.Fatalf("read: %q %v", b, err)
	}
	os.Remove(path)
	errs := make(chan error, 8)
	for i := range 8 {
		go func() { errs <- Create(path, []byte{byte('a' + i)}) }()
	}
	won := 0
	for range 8 {
		switch err := <-errs; {
		case err == nil:
			won++
		case !errors.Is(err, fs.ErrExist):
			t.Error(err)
		}
	}
	if won != 1 {
		t.Fatalf("%d created it", won)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("left behind: %v", ents)
	}
}
