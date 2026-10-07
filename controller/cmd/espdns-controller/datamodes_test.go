//go:build unix

package main

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/actionlog"
	"github.com/skitzo2000/espdns/controller/internal/boards"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
	"github.com/skitzo2000/espdns/controller/internal/jobs"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// Everything the controller writes in its data directory is its user's only, directories
// 0700 and files 0600, whatever the umask: under umask 000 (the most open) the data
// directory is made, a job runs (its record, the action log, the fleet lock), and the
// settings, a board and an edited file (with its history) are saved.
func TestDataModesUnderAnOpenUmask(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	if err := prepareData(dir, t.Logf); err != nil {
		t.Fatal(err)
	}
	r := jobs.New(dir, map[string]jobs.Kind{"noop": func(json.RawMessage) (jobs.Func, error) {
		return func(ctx context.Context, run *jobs.Run) (any, error) { run.Logf("ok"); return nil, nil }, nil
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	j, err := r.Start("noop", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if g, _ := r.Get(j.ID); g.State.Ended() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the job didn't end")
		}
	}
	cancel()
	<-done
	if err := actionlog.Append(dir, actionlog.Entry{Event: "save", ID: "x"}); err != nil {
		t.Fatal(err)
	}
	lk, err := fleetlock.Acquire(fleetlock.Path(dir), fleetlock.Self("test", "modes"))
	if err != nil {
		t.Fatal(err)
	}
	lk.Release()
	if err := settings.Save(settings.Path(dir), settings.Settings{}); err != nil {
		t.Fatal(err)
	}
	entries, err := boards.Load("../../../boards", "")
	if err != nil || len(entries) == 0 {
		t.Fatal(entries, err)
	}
	bd := entries[0].Board
	bd.Name = "mine"
	if err := boards.Save(filepath.Join(dir, "boards"), bd, entries); err != nil {
		t.Fatal(err)
	}
	st := filestore.Store{Dir: filepath.Join(dir, "zones"), Name: func(string) error { return nil }, Max: 1 << 10, Keep: 2}
	if err := st.Save("a.zone", []byte("one"), ""); err != nil {
		t.Fatal(err)
	}
	if err := st.Save("a.zone", []byte("two"), filestore.Hash([]byte("one"))); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		fi, _ := d.Info()
		rel, _ := filepath.Rel(dir, p)
		seen[filepath.ToSlash(rel)] = true
		want := fs.FileMode(0o600)
		if d.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: %04o, want %04o", rel, fi.Mode().Perm(), want)
		}
		return nil
	})
	for _, p := range []string{".", "fleet.lock", "log/actions.jsonl", "log/jobs/" + j.ID + ".json", "settings.json",
		"boards/mine.json", "zones/a.zone", "zones/.history"} {
		if !seen[p] {
			t.Errorf("%s: not written (seen %v)", p, seen)
		}
	}
}
