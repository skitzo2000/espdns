// Package filestore is a directory of text files the controller edits (the node configs,
// the hosted zones): each saved whole or not at all, mode 0600, only over the version the
// edit started from, the version replaced (or deleted) kept in a history beside them:
//
//	<dir>/<name>                 the file
//	<dir>/.history/<name>.<time> the versions a save replaced or a delete removed, the newest Keep
//
// The controller is the only writer here: a file changed by hand meanwhile is caught by its
// hash, not overwritten.
package filestore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// HistoryDir is the history's directory in a store's.
const HistoryDir = ".history"

// Store is one directory of files.
type Store struct {
	Dir string
	// Name refuses a file name the store doesn't take (a plain name, no directories).
	Name func(name string) error
	// Check refuses text the store doesn't save (nil: any).
	Check func(name string, text []byte) error
	// Max is the most a file may hold.
	Max int64
	// Keep is how many earlier versions of each file are kept.
	Keep int
}

// Hash is the sha256 of a file's bytes, hex: a save names the version it edited by it.
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// File is one file read.
type File struct {
	Name     string
	Modified time.Time
	Text     []byte
	Hash     string
}

// ErrChanged: the file isn't the version the save was made from.
var ErrChanged = errors.New("the file changed since it was loaded: load it again, and redo the edit on that")

// Read reads one file by name.
func (s Store) Read(name string) (File, error) {
	if err := s.Name(name); err != nil {
		return File{}, err
	}
	p := filepath.Join(s.Dir, name)
	fi, err := os.Stat(p)
	if err != nil {
		return File{}, err
	}
	if !fi.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s: not a regular file", p)
	}
	if fi.Size() > s.Max {
		return File{}, fmt.Errorf("%s: over %d bytes", p, s.Max)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return File{}, err
	}
	return File{Name: name, Modified: fi.ModTime(), Text: b, Hash: Hash(b)}, nil
}

// Names are the files in the directory whose names the store takes, sorted; none if there
// is no directory.
func (s Store) Names() ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if s.Name(e.Name()) == nil {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// mu makes a save's (or delete's) compare with the version edited and its write one step,
// so two saves from the same version can't both pass the compare and the second silently
// overwrite the first.
var mu sync.Mutex

// current is the file as it is now, checked against expect: the hash of the version the
// edit started from ("" for a file that must not exist yet). nil if there is none.
func (s Store) current(name, expect string) ([]byte, error) {
	p := filepath.Join(s.Dir, name)
	old, err := os.ReadFile(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if expect != "" {
			return nil, fmt.Errorf("%s: %w (it is gone)", name, ErrChanged)
		}
		old = nil
	case err != nil:
		return nil, err
	case expect == "":
		return nil, fmt.Errorf("%s already exists", name)
	case Hash(old) != expect:
		return nil, fmt.Errorf("%s: %w", name, ErrChanged)
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symbolic link: edit the file it points to, or replace the link with the file", p)
	}
	return old, nil
}

// Save writes a file, checked (Check), whole or not at all, mode 0600. expect is the hash of
// the version the edit started from ("" for a new file, which must not exist); the version
// replaced goes to the history first.
func (s Store) Save(name string, text []byte, expect string) error {
	if err := s.Name(name); err != nil {
		return err
	}
	if int64(len(text)) > s.Max {
		return fmt.Errorf("over %d bytes", s.Max)
	}
	if s.Check != nil {
		if err := s.Check(name, text); err != nil {
			return err
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if err := secfile.MkdirAll(s.Dir); err != nil {
		return err
	}
	old, err := s.current(name, expect)
	if err != nil {
		return err
	}
	if old != nil {
		if err := s.keep(name, old); err != nil {
			return fmt.Errorf("keeping the version before: %w", err)
		}
	}
	return WriteFile(filepath.Join(s.Dir, name), text)
}

// Delete removes a file, the version expect names (its hash), after keeping it in the
// history: it can be had back from there.
func (s Store) Delete(name, expect string) error {
	if err := s.Name(name); err != nil {
		return err
	}
	if expect == "" {
		return errors.New("a delete names the version it deletes (its hash)")
	}
	mu.Lock()
	defer mu.Unlock()
	old, err := s.current(name, expect)
	if err != nil {
		return err
	}
	if err := s.keep(name, old); err != nil {
		return fmt.Errorf("keeping it in the history: %w", err)
	}
	if err := os.Remove(filepath.Join(s.Dir, name)); err != nil {
		return err
	}
	syncDir(s.Dir)
	return nil
}

// WriteFile writes b to path whole or not at all, mode 0600, synced before the rename.
func WriteFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// historyTime is how a kept version's time is written into its name (sorts by time).
const historyTime = "20060102T150405.000000000Z"

// keep puts b, the version of name a save replaces, in the history, and drops the oldest
// beyond Keep.
func (s Store) keep(name string, b []byte) error {
	dir := filepath.Join(s.Dir, HistoryDir)
	if err := secfile.MkdirAll(dir); err != nil {
		return err
	}
	if err := WriteFile(filepath.Join(dir, name+"."+time.Now().UTC().Format(historyTime)), b); err != nil {
		return err
	}
	h, err := s.History(name)
	if err != nil {
		return err
	}
	for len(h) > s.Keep {
		os.Remove(filepath.Join(dir, h[len(h)-1].File))
		h = h[:len(h)-1]
	}
	return nil
}

// Version is one kept earlier version of a file.
type Version struct {
	File string    `json:"file"` // its name in the history directory
	Time time.Time `json:"time"` // when a save replaced it, or a delete removed it
	Size int64     `json:"size"`
}

// History is the kept versions of name, newest first.
func (s Store) History(name string) ([]Version, error) {
	ents, err := os.ReadDir(filepath.Join(s.Dir, HistoryDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Version
	for _, e := range ents {
		ts, ok := strings.CutPrefix(e.Name(), name+".")
		if !ok {
			continue
		}
		t, err := time.Parse(historyTime, ts)
		if err != nil {
			continue
		}
		v := Version{File: e.Name(), Time: t}
		if fi, err := e.Info(); err == nil {
			v.Size = fi.Size()
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b Version) int { return b.Time.Compare(a.Time) })
	return out, nil
}

// Kept is the names with versions in the history but no file now (deleted), each with its
// newest version.
func (s Store) Kept() (map[string]Version, error) {
	ents, err := os.ReadDir(filepath.Join(s.Dir, HistoryDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]Version{}
	for _, e := range ents {
		i := strings.LastIndexByte(e.Name(), '.')
		if i < 0 {
			continue
		}
		// <name>.<time>: the time has one '.' of its own.
		j := strings.LastIndexByte(e.Name()[:i], '.')
		if j < 0 {
			continue
		}
		name, ts := e.Name()[:j], e.Name()[j+1:]
		t, err := time.Parse(historyTime, ts)
		if err != nil || s.Name(name) != nil {
			continue
		}
		if _, err := os.Lstat(filepath.Join(s.Dir, name)); err == nil {
			continue
		}
		if v, ok := out[name]; !ok || t.After(v.Time) {
			nv := Version{File: e.Name(), Time: t}
			if fi, err := e.Info(); err == nil {
				nv.Size = fi.Size()
			}
			out[name] = nv
		}
	}
	return out, nil
}

// ReadVersion is a kept version of name, by its file name in the history.
func (s Store) ReadVersion(name, file string) ([]byte, error) {
	if err := s.Name(name); err != nil {
		return nil, err
	}
	ts, ok := strings.CutPrefix(file, name+".")
	if !ok || strings.ContainsAny(file, "/\\") {
		return nil, fmt.Errorf("%q is not a kept version of %s", file, name)
	}
	if _, err := time.Parse(historyTime, ts); err != nil {
		return nil, fmt.Errorf("%q is not a kept version of %s", file, name)
	}
	p := filepath.Join(s.Dir, HistoryDir, file)
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > s.Max {
		return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", p, s.Max)
	}
	return os.ReadFile(p)
}
