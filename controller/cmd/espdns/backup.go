package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/skitzo2000/espdns/controller/internal/backup"
	"github.com/skitzo2000/espdns/controller/internal/fleetlock"
)

// MinPassphrase is the shortest passphrase a backup takes.
const MinPassphrase = 12

// espdns backup -data /data -out <file>|- [-firmware] [-recipient age1...] [-wait 10m]
//
// Writes the data directory to one encrypted file (internal/backup): to a passphrase, from
// the terminal (asked twice, not echoed) or else the first line of standard input, never an
// argument or the environment; or to age public keys (-recipient, repeated). It takes the
// fleet lock while it reads, waiting up to -wait while a rollout or a job holds it.
func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dataDir := dataFlag(fs)
	out := fs.String("out", "", "the backup file to write (it must not exist), or - for standard output")
	firmware := fs.Bool("firmware", false, "include firmware/ (the boards' builds and chip images: made again by make, and the largest part)")
	var recips listFlag
	fs.Var(&recips, "recipient", "an age public key (age1...) to encrypt to instead of a passphrase; repeat for several")
	wait := fs.Duration("wait", 10*time.Minute, "how long to wait for the fleet lock while a rollout or a job holds it (0: not at all)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("need -out <file> (or - for standard output)")
	}
	if fi, err := os.Stat(*dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("-data %s: not a directory", *dataDir)
	}
	if *out == "-" && term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("-out -: standard output is a terminal; redirect it to a file")
	}
	if *out != "-" {
		if _, err := os.Lstat(*out); err == nil {
			return fmt.Errorf("-out %s: already exists; a backup never replaces a file", *out)
		}
	}
	var rs []age.Recipient
	how := "the passphrase"
	if len(recips) > 0 {
		parsed, err := age.ParseRecipients(strings.NewReader(strings.Join(recips, "\n")))
		if err != nil {
			return fmt.Errorf("-recipient: %w", err)
		}
		rs, how = parsed, fmt.Sprintf("%d age key(s)", len(parsed))
	} else {
		p, err := readPassphrase(os.Stdin, true)
		if err != nil {
			return err
		}
		r, _, err := backup.Passphrase(p)
		if err != nil {
			return err
		}
		rs = []age.Recipient{r}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lk, err := backup.Lock(ctx, *dataDir, "espdns backup", *wait, func(h fleetlock.Holder) {
		log.Printf("the fleet lock is held by %s: waiting up to %s for it", h, *wait)
	})
	if err != nil {
		return err
	}
	defer lk.Release()

	w, done, err := output(*out)
	if err != nil {
		return err
	}
	s, err := backup.Write(*dataDir, w, rs, backup.Options{Firmware: *firmware, Context: ctx})
	if err = done(err); err != nil {
		return err
	}
	where := *out
	if where == "-" {
		where = "standard output"
	}
	log.Printf("backup of %s to %s, encrypted to %s: %d files, %d directories, %s", *dataDir, where, how, s.Files, s.Dirs, size(s.Bytes))
	log.Printf("left out: %s", strings.Join(s.Excluded, "; "))
	for _, sk := range s.Skipped {
		log.Printf("skipped: %s", sk)
	}
	return nil
}

// output is where a backup goes: standard output, or a new file (mode 0600) written under a
// temporary name and renamed into place once whole. done(err) finishes it, or removes it if
// err.
func output(path string) (io.Writer, func(error) error, error) {
	if path == "-" {
		return os.Stdout, func(err error) error { return err }, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, nil, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	return bw, func(err error) error {
		if err == nil {
			err = bw.Flush()
		}
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			// Never over a file made meanwhile (a hard link fails if one is there); where
			// the filesystem has no hard links, renamed.
			if err = os.Link(f.Name(), path); err == nil {
				os.Remove(f.Name())
				return nil
			} else if !errors.Is(err, os.ErrExist) {
				if err = os.Rename(f.Name(), path); err == nil {
					return nil
				}
			}
		}
		os.Remove(f.Name())
		return err
	}, nil
}

func size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// readPassphrase reads a backup's passphrase: on a terminal asked (twice when twice),
// without echo; from anything else its first line. A new one (twice) is at least
// MinPassphrase characters.
func readPassphrase(in *os.File, twice bool) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(io.LimitReader(in, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		p := strings.TrimRight(line, "\r\n")
		if p == "" {
			return "", errors.New("no passphrase on standard input")
		}
		if twice && len(p) < MinPassphrase {
			return "", fmt.Errorf("the passphrase: at least %d characters", MinPassphrase)
		}
		return p, nil
	}
	ask := func(q string) (string, error) {
		fmt.Fprint(os.Stderr, q)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	if !twice {
		p, err := ask("the backup's passphrase: ")
		if err == nil && p == "" {
			err = errors.New("no passphrase given")
		}
		return p, err
	}
	fmt.Fprintf(os.Stderr, "a passphrase for the backup, at least %d characters: keep it apart from the backup (a password manager)\n", MinPassphrase)
	a, err := ask("passphrase: ")
	if err != nil {
		return "", err
	}
	if len(a) < MinPassphrase {
		return "", fmt.Errorf("the passphrase: at least %d characters", MinPassphrase)
	}
	b, err := ask("again: ")
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("the two passphrases differ: nothing written")
	}
	return a, nil
}

// printable is a backup's own text (the manifest's host and directory, the end's skipped
// names) as the terminal is given it: quoted if it holds anything not printable, so a
// crafted backup can't send the terminal escape sequences. The entries' paths are checked
// as printable already.
func printable(s string) string {
	if strings.ContainsFunc(s, func(r rune) bool { return r != ' ' && !unicode.IsPrint(r) }) {
		return strconv.Quote(s)
	}
	return s
}

// espdns restore -data /data -in <file>|- [-dry-run] [-force] [-identity <file>]
//
// Restores a backup into the data directory, which must be empty (or -force: what is there
// is moved into .before-restore-<time>/ first) and must not have a controller running on it.
// Everything is checked before anything is put in place (internal/backup). The passphrase
// is asked on the terminal, else read from standard input's first line (with -in -, the
// terminal only); -identity is an age identity file instead. -dry-run lists what the backup
// holds and checks it all, writing nothing.
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dataDir := dataFlag(fs)
	in := fs.String("in", "", "the backup file, or - for standard input")
	dry := fs.Bool("dry-run", false, "list and check the backup; write nothing")
	force := fs.Bool("force", false, "restore into a data directory that isn't empty, moving what is there aside first")
	identity := fs.String("identity", "", "an age identity file (AGE-SECRET-KEY-1...) for a backup made with -recipient")
	fs.Parse(args)
	if *in == "" {
		return errors.New("need -in <file> (or - for standard input)")
	}
	src := io.Reader(os.Stdin)
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			return err
		}
		defer f.Close()
		src = f
	}
	if !*dry {
		if empty, err := backup.Empty(*dataDir); err != nil {
			return err
		} else if !empty && !*force {
			return fmt.Errorf("%w: %s (restore into an empty one, or -force to move what is there aside first)", backup.ErrNotEmpty, *dataDir)
		}
	}
	var ids []age.Identity
	if *identity != "" {
		f, err := os.Open(*identity)
		if err != nil {
			return err
		}
		ids, err = age.ParseIdentities(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("-identity %s: %w", *identity, err)
		}
	} else {
		pin := os.Stdin
		if *in == "-" {
			tty, err := os.Open("/dev/tty")
			if err != nil {
				return errors.New("-in -: the backup is on standard input, so the passphrase is asked on the terminal, and there is none: give -in <file>")
			}
			defer tty.Close()
			pin = tty
		}
		p, err := readPassphrase(pin, false)
		if err != nil {
			return err
		}
		_, id, err := backup.Passphrase(p)
		if err != nil {
			return err
		}
		ids = []age.Identity{id}
	}
	c, err := backup.Restore(src, ids, *dataDir, backup.RestoreOptions{DryRun: *dry, Force: *force})
	if err != nil {
		return err
	}
	m := c.Manifest
	fmt.Printf("backup format %d, made %s on %s of %s; firmware/ %s\n", m.Format, m.Created.Local().Format("2006-01-02 15:04:05 MST"),
		printable(m.Host), printable(m.DataDir), map[bool]string{true: "included", false: "left out"}[m.Firmware])
	fmt.Printf("%d files, %d directories, %s; every file's sum checked\n", len(c.End.Files), c.End.Dirs, size(c.End.Bytes))
	for _, s := range c.End.Skipped {
		fmt.Printf("not in it: %s\n", printable(s))
	}
	for _, s := range c.Checked {
		fmt.Printf("checked: %s\n", s)
	}
	if *dry {
		for _, e := range c.Entries {
			if e.Dir {
				fmt.Printf("  %v %10s  %s  %s/\n", e.Mode, "", e.ModTime.Local().Format("2006-01-02 15:04"), e.Path)
			} else {
				fmt.Printf("  %v %10d  %s  %s\n", e.Mode, e.Size, e.ModTime.Local().Format("2006-01-02 15:04"), e.Path)
			}
		}
		fmt.Println("dry run: nothing written")
		return nil
	}
	if c.MovedAside != "" {
		fmt.Printf("what %s held is in %s\n", *dataDir, c.MovedAside)
	}
	fmt.Printf("restored into %s: start the controller on it (ESPDNS_DATA=<it> in .env, docker compose up -d), and log in with the restored login\n", *dataDir)
	return nil
}
