package secfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Everything in the data directory is the controller's user's only, not just the secrets:
// the fleet lock, the settings, the action log and the job records too (another local user
// could read the fleet's state, or hold the fleet lock). These are the modes, exactly,
// whatever the umask.
const (
	DirMode  fs.FileMode = 0o700
	FileMode fs.FileMode = 0o600
)

// MkdirAll makes path and every missing parent, each mode 0700 exactly (set after the
// mkdir, so the umask doesn't change it). A directory already there is left as it is:
// Tighten fixes the data directory's at start.
func MkdirAll(path string) error {
	fi, err := os.Stat(path)
	if err == nil {
		if fi.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if parent := filepath.Dir(path); parent != path {
		if err := MkdirAll(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(path, DirMode); err != nil {
		if fi, serr := os.Lstat(path); errors.Is(err, fs.ErrExist) && serr == nil && fi.IsDir() {
			return nil // made meanwhile
		}
		return err
	}
	return os.Chmod(path, DirMode)
}

// OpenFile opens path (not a link) with flag, made if missing, and leaves it mode 0600
// exactly: one made, whatever the umask, and one there with any other mode (a file from
// before, 0644) changed. A file it can't change (another user's) is an error.
func OpenFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|os.O_CREATE|noFollow, FileMode)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && fi.Mode().Perm() != FileMode {
		err = f.Chmod(FileMode)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// WriteFile writes data to path (made mode 0600 exactly, or truncated and left 0600), as
// os.WriteFile does: for a file whose readers take it whole or not at all, Write instead.
// It is truncated only once its mode is 0600: a file there it can't make so (another
// user's) is an error and left as it was, not emptied.
func WriteFile(path string, data []byte) error {
	f, err := OpenFile(path, os.O_WRONLY)
	if err != nil {
		return err
	}
	err = f.Truncate(0)
	if err == nil {
		_, err = f.Write(data)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Tighten takes group's and others' access away from root and everything in it: a
// directory open to them becomes 0700, a file 0600, as the controller makes them now (a data
// directory from before was 0755, its files 0644). Only what this user owns is changed, and
// only directories and regular files; links aren't followed (a link's target isn't the data
// directory's). It changes what it can and says what it changed; err joins what it couldn't
// (an unreadable directory, another user's file), which the caller reports, not fatal.
func Tighten(root string) (changed []string, err error) {
	var errs []error
	// The root itself may be a link (a data directory given by one): it is the data
	// directory, so it is followed, and only it. WalkDir wouldn't go into it.
	if fi, err := os.Lstat(root); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if root, err = filepath.EvalSymlinks(root); err != nil {
			return nil, err
		}
	}
	werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			if d != nil && d.IsDir() && p != root {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil // a link, a socket, a FIFO: left as it is
		}
		fi, err := d.Info()
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if fi.Mode().Perm()&0o077 == 0 {
			return nil
		}
		ok, err := tighten(p, d.IsDir())
		if err != nil {
			errs = append(errs, err)
		} else if ok {
			changed = append(changed, p)
		}
		return nil
	})
	if werr != nil {
		errs = append(errs, werr)
	}
	return changed, errors.Join(errs...)
}

// tighten changes p's mode, through a descriptor opened without following a link, so what
// is changed is what was checked: a directory or a regular file this user owns, open to
// group or others.
func tighten(p string, dir bool) (bool, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if fi.IsDir() != dir || (!dir && !fi.Mode().IsRegular()) || fi.Mode().Perm()&0o077 == 0 {
		return false, nil // changed meanwhile
	}
	if uid, ok := owner(fi); ok && uid != os.Geteuid() {
		return false, fmt.Errorf("%s: mode %04o, open to group or others, but owned by uid %d, not uid %d this runs as: not changed (chown it, or chmod go-rwx it)",
			p, fi.Mode().Perm(), uid, os.Geteuid())
	}
	want := FileMode
	if dir {
		want = DirMode
	}
	if err := f.Chmod(want); err != nil {
		return false, err
	}
	return true, nil
}
