package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/auth"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// A password piped in (no terminal) is read: the first line, without its line end.
func TestReadPasswordPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go func() { w.WriteString("scratch-test-pass-123\r\nsecond line\n"); w.Close() }()
	pw, err := readPassword(r, stdinWait)
	if err != nil || pw != "scratch-test-pass-123" {
		t.Fatalf("got %q, %v", pw, err)
	}
}

// A file on standard input, without a final newline, is read too.
func TestReadPasswordFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(f, []byte("scratch-test-pass-123"), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if pw, err := readPassword(in, stdinWait); err != nil || pw != "scratch-test-pass-123" {
		t.Fatalf("got %q, %v", pw, err)
	}
}

// Empty or closed standard input, an empty line, or /dev/null: the clear error, at once.
func TestReadPasswordEmptyFailsFast(t *testing.T) {
	for _, in := range []string{"", "\n", "\r\n"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.WriteString(in)
		w.Close()
		start := time.Now()
		_, err = readPassword(r, stdinWait)
		r.Close()
		if !errors.Is(err, errNoPassword) {
			t.Fatalf("%q: got %v, want errNoPassword", in, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%q: took %s", in, d)
		}
		if !strings.Contains(err.Error(), "no terminal") || !strings.Contains(err.Error(), "docker compose run --rm -T") {
			t.Fatalf("message: %v", err)
		}
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if _, err := readPassword(null, stdinWait); !errors.Is(err, errNoPassword) {
		t.Fatalf("/dev/null: got %v", err)
	}
}

// Standard input open with nobody writing to it: no hang, the clear error after the wait,
// and the notice of what it waits for once it has been silent a while.
func TestReadPasswordSilentStdinTimesOut(t *testing.T) {
	defer func(d time.Duration) { stdinNotice = d }(stdinNotice)
	stdinNotice = 20 * time.Millisecond
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	var notice strings.Builder
	start := time.Now()
	_, err = readPasswordLine(r, 100*time.Millisecond, &notice)
	if !errors.Is(err, errNoPassword) || !strings.Contains(err.Error(), "nothing within") {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	if !strings.Contains(notice.String(), "waiting for the password") {
		t.Fatalf("notice: %q", notice.String())
	}
}

// A slow writer (a password manager waiting for an MFA approval) is not cut
// off: the line written after the notice, within the wait, is the password, and neither
// the notice nor anything else shows it. The default wait outlasts a 180 s MFA prompt.
func TestReadPasswordSlowWriter(t *testing.T) {
	if stdinWait < 200*time.Second {
		t.Fatalf("stdinWait %s: shorter than an MFA approval (180 s) and the fetch after it", stdinWait)
	}
	defer func(d time.Duration) { stdinNotice = d }(stdinNotice)
	stdinNotice = 20 * time.Millisecond
	for _, wait := range []time.Duration{5 * time.Second, 0} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			time.Sleep(200 * time.Millisecond)
			w.WriteString("scratch-test-pass-123\n")
			w.Close()
		}()
		var notice strings.Builder
		pw, err := readPasswordLine(r, wait, &notice)
		r.Close()
		if err != nil || pw != "scratch-test-pass-123" {
			t.Fatalf("wait %s: got %q, %v", wait, pw, err)
		}
		if !strings.Contains(notice.String(), "waiting for the password") || strings.Contains(notice.String(), "scratch-test") {
			t.Fatalf("wait %s: notice %q", wait, notice.String())
		}
	}
}

// espdns passwd: with the password on a pipe it writes auth.json, mode 0600; with nothing
// on standard input it fails with the clear error and writes nothing; the error for a too
// short password never holds it.
func TestCmdPasswdNoTerminal(t *testing.T) {
	auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1}
	dir := t.TempDir()
	stdin(t, "")
	if err := cmdPasswd([]string{"-data", dir}); !errors.Is(err, errNoPassword) {
		t.Fatalf("empty stdin: %v", err)
	}
	if _, err := os.Stat(auth.Path(dir)); !os.IsNotExist(err) {
		t.Fatalf("auth.json written from empty stdin: %v", err)
	}
	stdin(t, "shortpw\n")
	if err := cmdPasswd([]string{"-data", dir}); err == nil || strings.Contains(err.Error(), "shortpw") {
		t.Fatalf("short password: %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old; r.Close() }()
	w.WriteString("scratch-test-pass-123\n")
	w.Close()
	if err := cmdPasswd([]string{"-data", dir}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(auth.Path(dir))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json: %v %v", fi, err)
	}
}

// The terminal's user name question: Enter keeps the name shown; a name typed is taken
// (trimmed); a bad one is refused; nothing past the line (the password) is read.
func TestPromptUser(t *testing.T) {
	for _, c := range []struct{ in, want, err string }{
		{"\n", "admin", ""},
		{"\r\n", "admin", ""},
		{"alice\n", "alice", ""},
		{"  alice  \n", "alice", ""},
		{"alice", "alice", ""},
		{"two words\n", "", "white space"},
		{"it's\n", "", "quotes"},
		{strings.Repeat("a", auth.MaxUser+1) + "\n", "", "too long"},
		{strings.Repeat("a", 1000) + "\n", "", "too long"},
		{"", "", "no answer"},
		{"\x1b[A\n", "", "printable"},
	} {
		var out strings.Builder
		got, err := promptUser(strings.NewReader(c.in), &out, "admin")
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%q: got %q, %v; want error %q", c.in, got, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
		}
		if out.String() != "user name [admin]: " {
			t.Errorf("%q: prompt %q", c.in, out.String())
		}
	}
	for _, in := range []string{"\n", "  \n", ""} { // no name to keep: an answer is needed
		var out strings.Builder
		if got, err := promptUser(strings.NewReader(in), &out, ""); err == nil || out.String() != "user name: " {
			t.Errorf("no current, %q: got %q, %v, prompt %q", in, got, err, out.String())
		}
	}
	r := strings.NewReader("alice\nscratch-test-pass-123\n")
	if got, err := promptUser(r, io.Discard, "admin"); err != nil || got != "alice" {
		t.Fatalf("got %q, %v", got, err)
	}
	if rest, _ := io.ReadAll(r); string(rest) != "scratch-test-pass-123\n" {
		t.Fatalf("the password line was read too: left %q", rest)
	}
}

// passwd -user: the name goes into auth.json, the message says it, a bad name is refused
// before anything is read or written; without -user (no terminal) the name set before is
// kept, and with no auth.json it is auth.DefaultUser.
func TestCmdPasswdUser(t *testing.T) {
	auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1}
	dir := t.TempDir()
	run := func(args ...string) (string, error) {
		stdin(t, "scratch-test-pass-123\n")
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = w
		err = cmdPasswd(append([]string{"-data", dir}, args...))
		os.Stdout = old
		w.Close()
		out, _ := io.ReadAll(r)
		r.Close()
		return string(out), err
	}
	user := func() string {
		c, err := auth.Load(auth.Path(dir))
		if err != nil {
			t.Fatal(err)
		}
		return c.User
	}
	for _, bad := range []string{"", "two words", "it's", "a\tb", "x\x01", strings.Repeat("a", 65)} {
		if _, err := run("-user", bad); err == nil || !strings.Contains(err.Error(), "-user") {
			t.Fatalf("-user %q: %v", bad, err)
		}
	}
	if _, err := os.Stat(auth.Path(dir)); !os.IsNotExist(err) {
		t.Fatalf("auth.json written for a bad name: %v", err)
	}
	out, err := run()
	if err != nil || user() != auth.DefaultUser || !strings.Contains(out, "password set for user "+auth.DefaultUser+" ") {
		t.Fatalf("default: %q %v %q", out, err, user())
	}
	out, err = run("-user", "alice")
	if err != nil || user() != "alice" || !strings.Contains(out, "password set for user alice ") ||
		!strings.Contains(out, "the user was admin before") {
		t.Fatalf("-user alice: %q %v %q", out, err, user())
	}
	out, err = run()
	if err != nil || user() != "alice" || !strings.Contains(out, "password set for user alice ") ||
		strings.Contains(out, "before:") {
		t.Fatalf("kept: %q %v %q", out, err, user())
	}
}

// An auth.json from an older passwd whose user name CheckUser no longer takes: without
// -user and no terminal, passwd says why and how to choose a new name, before reading the
// password, and changes nothing; -user replaces it, the old one shown quoted.
func TestCmdPasswdOldUser(t *testing.T) {
	auth.DefaultParams = auth.Params{Time: 1, MemoryKiB: 64, Threads: 1}
	dir := t.TempDir()
	old := "it's\x01"
	b, _ := json.Marshal(auth.Config{User: old, Hash: auth.Hash("scratch-test-pass-123", auth.DefaultParams)})
	if err := secfile.Write(auth.Path(dir), b); err != nil {
		t.Fatal(err)
	}
	stdin(t, "scratch-test-pass-456\n")
	err := cmdPasswd([]string{"-data", dir})
	if err == nil || !strings.Contains(err.Error(), "-user <name>") || !strings.Contains(err.Error(), `"it's\x01"`) {
		t.Fatalf("old name kept: %v", err)
	}
	if c, err := auth.Load(auth.Path(dir)); err != nil || c.User != old {
		t.Fatalf("auth.json changed: %q %v", c.User, err)
	}
	stdin(t, "scratch-test-pass-456\n")
	if err := cmdPasswd([]string{"-data", dir, "-user", "alice"}); err != nil {
		t.Fatal(err)
	}
	if c, err := auth.Load(auth.Path(dir)); err != nil || c.User != "alice" {
		t.Fatalf("new name: %q %v", c.User, err)
	}
}
