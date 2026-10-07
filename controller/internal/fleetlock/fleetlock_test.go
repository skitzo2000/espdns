package fleetlock

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// One taker at a time, in one process (each Acquire opens the file itself, as the
// controller's jobs do); a second taker learns who holds it; a released lock is free.
func TestAcquire(t *testing.T) {
	path := Path(t.TempDir())
	if _, held, err := Held(path); held || err != nil {
		t.Fatal(held, err)
	}
	l, err := Acquire(path, Self("espdns rollout", "rollout -kind firmware"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Acquire(path, Self("controller job 1", "check"))
	var le *LockedError
	if !errors.As(err, &le) || !errors.Is(err, ErrLocked) || le.Holder.Who != "espdns rollout" ||
		le.Holder.PID != os.Getpid() || !strings.Contains(err.Error(), "rollout -kind firmware") {
		t.Fatalf("%#v", err)
	}
	if h, held, err := Held(path); !held || err != nil || h.Who != "espdns rollout" {
		t.Fatal(h, held, err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if _, held, err := Held(path); held || err != nil {
		t.Fatal(held, err)
	}
	l2, err := Acquire(path, Self("controller job 1", "check"))
	if err != nil {
		t.Fatal(err)
	}
	l2.Release()
	l2.Release() // twice is harmless
}

// The data directory must be there: the lock never makes it.
func TestAcquireNoDir(t *testing.T) {
	if _, err := Acquire(Path(t.TempDir()+"/none"), Self("t", "")); err == nil || errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
}

// Two processes: the child takes the lock and waits; the parent can't take it and is told
// the child's PID; the child is killed (no Release: as a process or container that dies)
// and the lock is free at once, its holder file left behind.
func TestTwoProcesses(t *testing.T) {
	if os.Getenv("FLEETLOCK_CHILD") != "" {
		l, err := Acquire(os.Getenv("FLEETLOCK_CHILD"), Self("espdns reboot", "reboot -host 198.51.100.2"))
		if err != nil {
			os.Stdout.WriteString("error " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.WriteString("locked\n")
		time.Sleep(time.Minute)
		l.Release()
		os.Exit(0)
	}
	path := Path(t.TempDir())
	cmd := exec.Command(os.Args[0], "-test.run=^TestTwoProcesses$")
	cmd.Env = append(os.Environ(), "FLEETLOCK_CHILD="+path)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child: %q %v", line, err)
	}
	_, err = Acquire(path, Self("espdns rollout", ""))
	var le *LockedError
	if !errors.As(err, &le) || le.Holder.PID != cmd.Process.Pid || le.Holder.Who != "espdns reboot" {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "espdns reboot (reboot -host 198.51.100.2)") ||
		!strings.Contains(err.Error(), "one fleet change at a time") {
		t.Fatal(err)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "espdns reboot") {
		t.Fatalf("holder file: %q", b)
	}
	l, err := Acquire(path, Self("espdns rollout", ""))
	if err != nil {
		t.Fatalf("after the holder died: %v", err)
	}
	defer l.Release()
	if h, held, _ := Held(path); !held || h.Who != "espdns rollout" {
		t.Fatal(h, held)
	}
}

func TestHolderString(t *testing.T) {
	h := Holder{Who: "espdns rollout", What: "rollout -kind config", User: "alice", PID: 7, Container: "0123456789ab",
		Host: "box", Since: time.Now().Add(-90 * time.Second)}
	s := h.String()
	for _, want := range []string{"espdns rollout (rollout -kind config)", "alice pid 7 container 0123456789ab on box", "1m30s ago"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q: no %q", s, want)
		}
	}
	if s := (Holder{}).String(); !strings.Contains(s, "another process") {
		t.Error(s)
	}
}

// A lock held only for an instant (Held's probe, the Jobs page polling /api/lock) doesn't
// refuse a taker: it is tried again for a moment.
func TestAcquireBriefHolder(t *testing.T) {
	path := Path(t.TempDir())
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := tryLock(f); err != nil {
		t.Fatal(err)
	}
	unlocked := make(chan struct{})
	go func() {
		time.Sleep(3 * busyWait)
		unlock(f)
		close(unlocked)
	}()
	defer func() { <-unlocked }()
	l, err := Acquire(path, Self("espdns rollout", ""))
	if err != nil {
		t.Fatalf("refused by a brief holder: %v", err)
	}
	l.Release()
}
