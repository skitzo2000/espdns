// Package fleetlock is the fleet lock: one change to the nodes at a time, whoever makes it.
// Every espdns command that changes a node (rollout, reboot, adopt, config, zones, push,
// pause, identify, flush) and the controller's job runner take it before they touch a node,
// so two pushes never race a node's sequence numbers and two reboots never overlap.
//
// The lock is flock(2) on <data>/fleet.lock, the data directory the controller and the
// CLI's fleet targets share (controller/data, /data in their containers). The kernel holds
// it for the open file, so it goes when its holder exits however it exits: a killed process
// or container never leaves a stale lock. What the file holds is only who took it last (a
// JSON Holder), for the message a second taker gets; it is not the lock. flock works across
// containers on one host through a bind mount of a local filesystem (not over NFS) and needs
// nothing in the image: it is one system call, so the distroless image has it.
package fleetlock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// File is the lock file's name in the data directory.
const File = "fleet.lock"

// Path is the lock file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, File) }

// Holder says who holds the lock, for the message a second taker gets.
type Holder struct {
	Who       string    `json:"who"`  // "espdns rollout", "controller job 20261003-140211-ab12"
	What      string    `json:"what"` // what it is doing: the command's arguments, the job's kind
	User      string    `json:"user,omitempty"`
	Host      string    `json:"host,omitempty"`
	PID       int       `json:"pid"`
	Container string    `json:"container,omitempty"` // the Docker container ID, if it runs in one
	Since     time.Time `json:"since"`
}

// Self is a Holder for this process: its user, host, PID and container, since now.
func Self(who, what string) Holder {
	h := Holder{Who: who, What: what, PID: os.Getpid(), Since: time.Now()}
	h.Host, _ = os.Hostname()
	if u, err := user.Current(); err == nil && u.Username != "" {
		h.User = u.Username
	} else {
		h.User = "uid " + strconv.Itoa(os.Getuid())
	}
	h.Container = container()
	return h
}

var containerID = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)

// container is this process's Docker container ID (12 characters, as docker ps shows it),
// from where Docker mounted its hostname file; "docker" in one whose ID it can't find; ""
// outside a container.
func container() string {
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if m := containerID.FindSubmatch(b); m != nil {
			return string(m[1][:12])
		}
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	return ""
}

func (h Holder) String() string {
	if h.Who == "" {
		return "another process that left no note (one just starting, or firmware/'s make ota or bench-ota, " +
			"which hold the lock with flock(1))"
	}
	s := h.Who
	if h.What != "" {
		s += " (" + h.What + ")"
	}
	var where []string
	if h.User != "" {
		where = append(where, h.User)
	}
	if h.PID != 0 {
		where = append(where, "pid "+strconv.Itoa(h.PID))
	}
	if h.Container != "" {
		where = append(where, "container "+h.Container)
	}
	if h.Host != "" {
		where = append(where, "on "+h.Host)
	}
	if len(where) > 0 {
		s += ", " + strings.Join(where, " ")
	}
	if !h.Since.IsZero() {
		s += fmt.Sprintf(", since %s (%s ago)", h.Since.Local().Format("2006-01-02 15:04:05 MST"),
			time.Since(h.Since).Round(time.Second))
	}
	return s
}

// LockedError is what a second taker gets: who holds the lock.
type LockedError struct{ Holder Holder }

func (e *LockedError) Error() string {
	return "the fleet is locked by " + e.Holder.String() + ": one fleet change at a time; try again when it is done"
}

// ErrLocked matches a LockedError with errors.Is.
var ErrLocked = errors.New("the fleet is locked")

func (e *LockedError) Is(target error) bool { return target == ErrLocked }

// Lock is the fleet lock, held.
type Lock struct{ f *os.File }

// busyTries and busyWait: a lock found busy is tried again for a moment before a taker is
// refused, as Held (the controller's GET /api/lock, which the Jobs page polls) holds it for
// an instant to see whether anyone else does.
const (
	busyTries = 10
	busyWait  = 20 * time.Millisecond
)

// lockFile takes f's flock, trying again for a moment while it is busy.
func lockFile(f *os.File) error {
	var err error
	for i := 0; i < busyTries; i++ {
		if i > 0 {
			time.Sleep(busyWait)
		}
		if err = tryLock(f); !errors.Is(err, errBusy) {
			return err
		}
	}
	return err
}

// Acquire takes the lock at path for h, or fails (within busyTries*busyWait) with a
// *LockedError naming who has it. The directory must exist (the data directory): it is
// never made here.
func Acquire(path string, h Holder) (*Lock, error) {
	f, err := secfile.OpenFile(path, os.O_RDWR)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("fleet lock: %w (the data directory and %s must belong to the user running "+
				"espdns and the controller: a root-owned one is from a run as root)", err, File)
		}
		return nil, fmt.Errorf("fleet lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, errBusy) {
			return nil, &LockedError{Holder: holder(path)}
		}
		return nil, fmt.Errorf("fleet lock %s: %w", path, err)
	}
	b, _ := json.Marshal(h)
	if err := f.Truncate(0); err == nil {
		_, err = f.WriteAt(append(b, '\n'), 0)
	}
	if err != nil {
		unlock(f)
		f.Close()
		return nil, fmt.Errorf("fleet lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// holder reads who holds the lock. A taker writes it just after it gets the lock, so an
// empty file is retried for a moment.
func holder(path string) Holder {
	var h Holder
	for i := 0; i < 10; i++ {
		if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &h) == nil {
			return h
		}
		time.Sleep(20 * time.Millisecond)
	}
	return h
}

// Release lets the lock go. The file stays (with nothing in it): removing it would let a
// taker lock a new file while another waits on the old one.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.f.Truncate(0)
	err := unlock(l.f)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// Held says who holds the lock at path now, if anyone. With no lock file nobody does.
func Held(path string) (Holder, bool, error) {
	f, err := os.Open(path) // flock needs no write access
	if errors.Is(err, os.ErrNotExist) {
		return Holder{}, false, nil
	}
	if err != nil {
		return Holder{}, false, err
	}
	defer f.Close()
	switch err := lockFile(f); {
	case err == nil:
		unlock(f)
		return Holder{}, false, nil
	case errors.Is(err, errBusy):
		return holder(path), true, nil
	default:
		return Holder{}, false, err
	}
}
