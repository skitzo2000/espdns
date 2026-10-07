package actionlog

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestAppendTail(t *testing.T) {
	dir := t.TempDir()
	if es, err := Tail(dir, 10); err != nil || len(es) != 0 {
		t.Fatal(es, err)
	}
	for i, ev := range []string{"start", "end"} {
		e := Entry{Event: ev, ID: "cli-1", Source: "cli", Who: "alice@box", Action: "rollout", Args: []string{"-kind", "config"}}
		if i == 1 {
			e.Result, e.Duration = "ok", 1.5
		}
		if err := Append(dir, e); err != nil {
			t.Fatal(err)
		}
	}
	// A line cut short (a process killed mid-write) is skipped, not an error.
	f, _ := os.OpenFile(Path(dir), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"time":"2026-`)
	f.Close()
	es, err := Tail(dir, 0)
	if err != nil || len(es) != 2 || es[0].Event != "start" || es[1].Result != "ok" || es[1].Time.IsZero() {
		t.Fatalf("%+v %v", es, err)
	}
	b, _ := os.ReadFile(Path(dir))
	if !strings.HasPrefix(string(b), `{"time":`) || !strings.Contains(string(b), `"action":"rollout","args":["-kind","config"]`) {
		t.Fatalf("%s", b)
	}
}

// Past MaxBytes the log moves to .1 (replacing the one before), at a start entry only (one
// written under the fleet lock), and Tail reads both.
func TestRotate(t *testing.T) {
	dir := t.TempDir()
	pad := strings.Repeat("x", 1000)
	n := 0
	for rotations := 0; rotations < 2; n++ {
		before, _ := os.Stat(Path(dir))
		ev := []string{"start", "end", "refused"}[n%3]
		if err := Append(dir, Entry{Event: ev, ID: fmt.Sprint(n), Error: pad}); err != nil {
			t.Fatal(err)
		}
		after, _ := os.Stat(Path(dir))
		if before != nil && after.Size() < before.Size() {
			if ev != "start" {
				t.Fatalf("rotated at a %s entry", ev)
			}
			rotations++
		}
	}
	cur, _ := os.Stat(Path(dir))
	old, err := os.Stat(Path(dir) + ".1")
	if err != nil || old.Size() < MaxBytes || old.Size() > MaxBytes+4000 || cur.Size() > 2000 {
		t.Fatal(old, cur, err)
	}
	es, err := Tail(dir, 3)
	if err != nil || len(es) != 3 || es[2].ID != fmt.Sprint(n-1) {
		t.Fatalf("%v %v", len(es), err)
	}
	all, _ := Tail(dir, 0)
	if all[len(all)-1].ID != fmt.Sprint(n-1) || len(all) < MaxBytes/1200 {
		t.Fatal(len(all))
	}
}
