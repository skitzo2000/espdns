// Package actionlog is the action log: every change to the fleet, by the CLI or the
// controller, as JSON lines appended to <data>/log/actions.jsonl. Each change writes a
// "start" entry before it touches a node and an "end" entry with its result, both with the
// change's ID, so a change whose process died shows as a start with no end.
//
// Size: when the file is past MaxBytes, the next "start" entry first renames it to
// actions.jsonl.1 (replacing the one before), so the log holds between one and two
// MaxBytes of the newest entries. Each entry is one write (O_APPEND), so two writers never
// interleave. Only a "start" rotates, and a start is written by whoever just took the
// fleet lock, so two writers never rotate at once: a "refused" entry is written without
// the lock (its writer was refused it), and an "end" never splits a change from its start.
//
// A change that can't write its start entry (the log directory not writable) doesn't
// start: every change to the nodes is in the log. A failed end or refused entry is only
// reported.
package actionlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

const (
	Dir  = "log"           // in the data directory
	File = "actions.jsonl" // in Dir; the one before is File + ".1"
	// MaxBytes is the size past which the log is rotated.
	MaxBytes = 1 << 20
)

// Path is the action log in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, Dir, File) }

// Entry is one line of the log.
type Entry struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`  // "start" or "end"
	ID     string    `json:"id"`     // the change: a job's ID, or the CLI run's ("cli-...")
	Source string    `json:"source"` // "cli" or "controller"
	Who    string    `json:"who"`    // user@host (CLI), or who started the job
	Action string    `json:"action"` // "rollout", "reboot", "adopt", ..., or "job check"
	Args   []string  `json:"args,omitempty"`
	// End only: "ok", "failed" or "stopped", why, and how long it took.
	Result   string  `json:"result,omitempty"`
	Error    string  `json:"error,omitempty"`
	Duration float64 `json:"duration_s,omitempty"`
}

// Append writes e to the log in dataDir; a "start" entry (written under the fleet lock)
// rotates the log first if it is past MaxBytes.
func Append(dataDir string, e Entry) error {
	path := Path(dataDir)
	if err := secfile.MkdirAll(filepath.Dir(path)); err != nil {
		return err
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() >= MaxBytes && e.Event == "start" {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := secfile.OpenFile(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Tail returns the last n entries (all with n <= 0), oldest first, from the rotated file
// and the current one. A line that isn't an entry (one cut short) is skipped.
func Tail(dataDir string, n int) ([]Entry, error) {
	var out []Entry
	for _, p := range []string{Path(dataDir) + ".1", Path(dataDir)} {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), MaxBytes)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil && e.Event != "" {
				out = append(out, e)
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}
