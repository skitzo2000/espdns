package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/skitzo2000/espdns/controller/internal/auth"
)

// espdns passwd -data /data [-user name]
//
// Sets the controller's one login (internal/auth): its user name, the deployment's choice,
// and its password. On a terminal it asks for the name first (Enter keeps the one shown:
// the one set before, else auth.DefaultUser) unless -user gives it, then the password
// twice, not echoed. Without a terminal the name is -user's, else the one set before, else
// auth.DefaultUser, never asked; the password is the first line of standard input (a pipe
// or a file: make passwd with the password piped in, or PASSWD_FROM_ENV=1). Kept as an
// argon2id hash in <data>/auth.json, mode 0600. Every session before ends (a new name or
// password alike: each write is a new salted hash). The password is never an argument or in
// the environment. With no terminal and nothing on standard input (empty or closed: at
// once; open with nothing written: after -wait) it fails, never hangs.
func cmdPasswd(args []string) error {
	fl := flag.NewFlagSet("passwd", flag.ExitOnError)
	dataDir := dataFlag(fl)
	user := fl.String("user", "", "the user's name (default: asked on a terminal; else the one set before, else "+auth.DefaultUser+")")
	wait := fl.Duration("wait", stdinWait, "no terminal: how long standard input may stay silent before the first line (0: no limit)")
	fl.Parse(args)
	if fi, err := os.Stat(*dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("-data %s: not a directory (make it before you start the controller: docs/getting-started.md, step 5)", *dataDir)
	}
	path := auth.Path(*dataDir)
	before := ""
	if c, err := auth.Load(path); err == nil {
		before = c.User
	}
	// A name set before by an older espdns passwd that CheckUser no longer takes still logs
	// in, but can't be kept: a new one is needed, said so before the password is asked.
	beforeErr := error(nil)
	if before != "" {
		beforeErr = auth.CheckUser(before)
	}
	userSet := false
	fl.Visit(func(f *flag.Flag) { userSet = userSet || f.Name == "user" })
	name := *user
	switch {
	case userSet:
		if err := auth.CheckUser(name); err != nil {
			return fmt.Errorf("-user: %w", err)
		}
	case term.IsTerminal(int(os.Stdin.Fd())):
		def := before
		if def == "" {
			def = auth.DefaultUser
		}
		if beforeErr != nil {
			fmt.Fprintf(os.Stderr, "the user set before, %s, is not a name passwd takes now (%v): choose a new one\n",
				showUser(before), beforeErr)
			def = ""
		}
		var err error
		if name, err = promptUser(os.Stdin, os.Stderr, def); err != nil {
			return err
		}
	case beforeErr != nil:
		return fmt.Errorf("the user set before, %s, is not a name passwd takes now (%v): give a new one with "+
			"-user <name>; until then it still logs in", showUser(before), beforeErr)
	default:
		name = before
		if name == "" {
			name = auth.DefaultUser
		}
	}
	pw, err := readPassword(os.Stdin, *wait)
	if err != nil {
		return err
	}
	if err := auth.SetPassword(path, name, pw); err != nil {
		return err
	}
	fmt.Printf("password set for user %s in %s (mode 0600); sessions before end now\n", name, path)
	if before != "" && before != name {
		fmt.Printf("the user was %s before: log in as %s from now on\n", showUser(before), name)
	}
	return nil
}

// showUser is a user name as it can be shown: itself when CheckUser takes it, else quoted
// (a name set before by an older passwd may hold control characters).
func showUser(name string) string {
	if auth.CheckUser(name) == nil {
		return name
	}
	return fmt.Sprintf("%q", name)
}

// promptUser asks on w for the user name and reads one line of r: an empty line keeps
// current ("": there is none to keep, and an answer is needed). The name is checked
// (auth.CheckUser); a bad one is an error, nothing written. It reads a byte at a time, so
// nothing past the line (the password) is taken from r.
func promptUser(r io.Reader, w io.Writer, current string) (string, error) {
	if current != "" {
		fmt.Fprintf(w, "user name [%s]: ", current)
	} else {
		fmt.Fprint(w, "user name: ")
	}
	var line []byte
	b := make([]byte, 1)
	for len(line) <= 4*auth.MaxUser {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", errors.New("user name: no answer")
			}
			break
		}
		if err != nil {
			return "", fmt.Errorf("user name: %w", err)
		}
	}
	name := strings.TrimSpace(string(line))
	if name == "" {
		if current == "" {
			return "", errors.New("user name: no answer")
		}
		return current, nil
	}
	if err := auth.CheckUser(name); err != nil {
		return "", fmt.Errorf("user name: %w", err) // not the name: it may be a password typed too soon
	}
	return name, nil
}

// errNoPassword: no terminal to ask on and no password on standard input.
var errNoPassword = errors.New("no terminal and nothing on standard input: pipe the password in " +
	"(printf '%s\\n' \"$PW\" | docker compose run --rm -T --entrypoint /espdns espdns-controller passwd -data /data -user <name>)")

// stdinWait is how long (-wait) a standard input that is not a terminal may stay silent
// before passwd gives up. An open stream nobody writes to (a tool's shell, a CI step with
// stdin left open) would otherwise block for ever, but a pipe's writer may be slow for good
// reason: a password manager waiting for an unlock or an MFA approval in a
// browser (up to 180 s) before it writes. Under Docker -i the container's standard input
// is a pipe whatever the host's was, so the two cannot be told apart; the wait outlasts the
// slow writer, and passwd says what it is waiting for once the input has been silent for
// stdinNotice. Empty, closed or /dev/null standard input fails at once.
var (
	stdinWait   = 4 * time.Minute
	stdinNotice = 2 * time.Second
)

// readPassword asks twice on a terminal, without echo; from anything else it reads one
// line, waiting at most wait for it (0: no limit).
func readPassword(in *os.File, wait time.Duration) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		return readPasswordLine(in, wait, os.Stderr)
	}
	ask := func(q string) (string, error) {
		fmt.Fprint(os.Stderr, q)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	fmt.Fprintf(os.Stderr, "at least %d characters\n", auth.MinPassword)
	a, err := ask("new password: ")
	if err != nil {
		return "", err
	}
	if err := auth.CheckPassword(a); err != nil {
		return "", fmt.Errorf("password: %w", err)
	}
	b, err := ask("again: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("the two passwords differ: nothing changed")
	}
	return a, nil
}

// readPasswordLine reads the first line of r, waiting at most wait for it (0: no limit),
// and says on notice what it waits for if r stays silent for stdinNotice. Nothing (an
// empty or closed input, an empty line, or silence until wait) is errNoPassword. The
// password is never in an error. On a timeout the reading goroutine stays blocked on r;
// passwd returns and the process exits, so it holds nothing up.
func readPasswordLine(r io.Reader, wait time.Duration, notice io.Writer) (string, error) {
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(r, 4096)).ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		done <- result{strings.TrimRight(line, "\r\n"), err}
	}()
	var timeout <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	var noticeC <-chan time.Time
	if notice != nil && (wait <= 0 || stdinNotice < wait) {
		n := time.NewTimer(stdinNotice)
		defer n.Stop()
		noticeC = n.C
	}
	for {
		select {
		case res := <-done:
			if res.err != nil {
				return "", fmt.Errorf("standard input: %w", res.err)
			}
			if res.line == "" {
				return "", errNoPassword
			}
			return res.line, nil
		case <-noticeC:
			noticeC = nil
			limit := "no time limit"
			if wait > 0 {
				limit = "up to " + wait.String()
			}
			fmt.Fprintf(notice, "no terminal: waiting for the password's line on standard input (%s; -wait)\n", limit)
		case <-timeout:
			return "", fmt.Errorf("%w (nothing within %s)", errNoPassword, wait)
		}
	}
}
