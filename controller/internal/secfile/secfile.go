// Package secfile reads and writes the controller's secret files in the data directory
// (the release key, the login's password hash): mode 0600, owned by the user the
// controller runs as, never readable by anyone else. A file that is, is refused, not used.
// It also has what makes the rest of the data directory the controller's user's only
// (private.go): directories 0700 and files 0600, whatever the umask, and Tighten, which
// fixes a data directory made before.
package secfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxSize is the most a secret file may hold: a PEM key or a password hash is far smaller.
const MaxSize = 64 << 10

// Read reads a secret file that passes Check. A missing file is fs.ErrNotExist (errors.Is).
func Read(path string) ([]byte, error) {
	if err := Check(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := check(path, fi); err != nil { // the file opened, not one put there since
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("%s: over %d bytes", path, MaxSize)
	}
	return b, nil
}

// Check says whether path is a regular file (not a link), readable and writable by its
// owner only, and owned by the user this process runs as.
func Check(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: a symbolic link, so not used: the file itself must be in the data directory", path)
	}
	return check(path, fi)
}

func check(path string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file (%v)", path, fi.Mode().Type())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o: open to group or others, so not used: chmod 600 %s", path, perm, path)
	}
	if uid, ok := owner(fi); ok && uid != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not uid %d this runs as, so not used", path, uid, os.Geteuid())
	}
	return nil
}

// Stamp is what changes when the file is written, replaced, chmod-ed or chown-ed (its
// modification time, inode, size, mode and owner): a reader that keeps the file's contents reads it again
// when its Stamp changes, so a file opened up to others is refused from then on, and one
// fixed is used again. The zero Stamp: no file.
type Stamp struct {
	mod  int64
	ino  uint64
	size int64
	mode fs.FileMode
	uid  int
}

// StampOf is path's Stamp now (not following a link), or the zero Stamp.
func StampOf(path string) Stamp {
	fi, err := os.Lstat(path)
	if err != nil {
		return Stamp{}
	}
	uid, _ := owner(fi)
	return Stamp{mod: fi.ModTime().UnixNano(), ino: inode(fi), size: fi.Size(), mode: fi.Mode(), uid: uid}
}

// Write replaces path with data, mode 0600, through a temporary file in the same
// directory (made 0700 if missing), so a reader sees the old file or the new, never part of
// one, and the secret is never in a file anyone else can read.
func Write(path string, data []byte) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return errors.New(path + ": not a regular file: not replaced")
	}
	return write(path, data, os.Rename)
}

// Create is Write for a file that must not exist yet: of two creating it at once (or one
// made by anything else first) only one succeeds, the other gets fs.ErrExist (errors.Is)
// and changes nothing. The whole file appears at once, as with Write: the temporary file
// is linked to path, which fails if anything is there.
func Create(path string, data []byte) error {
	return write(path, data, func(tmp, path string) error {
		if err := os.Link(tmp, path); err != nil {
			return err
		}
		os.Remove(tmp) // the file is made: a temporary name left over doesn't undo that
		return nil
	})
}

// write writes data to a temporary file next to path (mode 0600, synced) and puts it at
// path with place.
func write(path string, data []byte, place func(tmp, path string) error) (err error) {
	dir := filepath.Dir(path)
	if err := MkdirAll(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := place(f.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
