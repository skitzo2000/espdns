package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

// espdns primary import -data /data [-replace]
// espdns primary status -data /data
// espdns primary cert -data /data
// espdns primary pin -data /data -sha256 <fingerprint>
// espdns primary unpin -data /data
//
// The controller's zone primary API token (internal/primary: a kind driven over an API):
// <data>/keys/primary.token, mode 0600 (internal/keys). import reads it from standard input (as
// make primary-import pipes it from an environment variable, PRIMARY_TOKEN_ENV, or a file), never an
// argument or the environment, and writes it; the same token again changes nothing, a different one needs -replace.
// status says which zone primary settings.json names and whether the token is there and
// usable (0600, this user's), never the token. Neither calls the primary.
//
// cert, pin and unpin are the confirm step for a primary with its own (self-signed)
// certificate (internal/primary, tls.go): cert shows the certificate the primary in
// settings.json presents (read in a TLS handshake: nothing else is sent, no token) and its
// SHA-256 fingerprint; pin, once that fingerprint is checked on the primary, pins it in
// settings.json, if the primary still presents it; unpin takes the pin away.
func cmdPrimary(name string, args []string) error {
	if len(args) < 1 || !slices.Contains([]string{"import", "status", "cert", "pin", "unpin"}, args[0]) {
		return fmt.Errorf("usage: espdns %s import|status|cert|pin|unpin -data <dir>", name)
	}
	sub, args := args[0], args[1:]
	if sub == "cert" || sub == "pin" || sub == "unpin" {
		return cmdPrimaryCert(name, sub, args, os.Stdout)
	}
	fs := flag.NewFlagSet(name+" "+sub, flag.ExitOnError)
	dataDir := dataFlag(fs)
	replace := false
	if sub == "import" {
		fs.BoolVar(&replace, "replace", false, "replace a different token imported before")
	}
	fs.Parse(args)
	src := keys.DataTokenSource{DataDir: *dataDir}
	if sub == "status" {
		primaryStatus(*dataDir, os.Stdout)
		if _, err := src.Token(); err != nil {
			return err
		}
		fmt.Printf("%s: mode 0600, owned by this user, a token: the controller edits the zone primary's allow lists with it\n", src.Path())
		return nil
	}
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("%s import reads the token from standard input, piped (docs/reference/cli.md#primary), not typed", name)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return fmt.Errorf("standard input: %w", err)
	}
	tok, err := keys.ParseToken("the token on standard input", b)
	if err != nil {
		return err
	}
	if fi, err := os.Stat(*dataDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("-data %s: not a directory (make it before you start the controller: docs/getting-started.md, step 5)", *dataDir)
	}
	same, err := keys.ImportDataToken(*dataDir, tok, replace)
	if err != nil {
		return err
	}
	path := keys.TokenPath(*dataDir)
	if same {
		fmt.Printf("%s: already this token; nothing changed\n", path)
	} else {
		fmt.Printf("imported to %s (mode 0600): the controller uses it from its next adoption or zone primary read\n", path)
	}
	return nil
}

// primaryStatus is status's first lines: the zone primary settings.json names, and, at a
// plain http address, that it is paused and why.
func primaryStatus(dataDir string, out io.Writer) {
	s, serr := settings.Load(settings.Path(dataDir))
	switch zp := s.ZonePrimary(); {
	case serr != nil:
		fmt.Fprintf(out, "settings.json: %v\n", serr)
	case zp.IsZero():
		fmt.Fprintln(out, `zone primary: none in settings.json ("primary"): treated as manual, its lists changed by hand`)
	default:
		fmt.Fprintf(out, "zone primary: %s (settings.json)\n", zp)
		if zp.PlainHTTP() {
			fmt.Fprintf(out, "zone primary: paused: %v (nothing is sent to it, the token never)\n", primary.ErrPlainHTTP)
		}
	}
}

// cmdPrimaryCert is espdns primary cert|pin|unpin.
func cmdPrimaryCert(name, sub string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(name+" "+sub, flag.ExitOnError)
	dataDir := dataFlag(fs)
	sha := ""
	if sub == "pin" {
		fs.StringVar(&sha, "sha256", "", "the fingerprint espdns primary cert shows, once checked on the primary")
	}
	fs.Parse(args)
	path := settings.Path(*dataDir)
	s, err := settings.Load(path)
	if err != nil {
		return err
	}
	zp := s.ZonePrimary()
	if zp.URL == "" {
		return errors.New(`settings.json names no zone primary reached over an API ("primary": {"kind", "url"})`)
	}
	if sub == "unpin" {
		if err := settings.SetPrimaryPin(path, zp.URL, ""); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: no certificate pinned; only one the system's roots trust is accepted\n", zp.URL)
		return nil
	}
	var fp string
	if sub == "pin" {
		if fp, err = primary.ParseFingerprint(sha); err != nil {
			return fmt.Errorf("-sha256: %w (espdns %s cert shows it)", err, name)
		}
	}
	info, err := primary.Presented(context.Background(), zp.URL)
	if err != nil {
		return err
	}
	if sub == "cert" {
		fmt.Fprintf(out, "zone primary %s presents:\n  SHA-256   %s\n  subject   %s\n  issuer    %s\n  names     %s\n  valid     %s to %s\n",
			zp.URL, info.SHA256, info.Subject, info.Issuer, strings.Join(info.Names, ", "),
			info.NotBefore.Format(time.DateOnly), info.NotAfter.Format(time.DateOnly))
		switch {
		case zp.CertSHA256 == info.SHA256:
			fmt.Fprintln(out, "pinned: this certificate")
		case zp.CertSHA256 != "":
			fmt.Fprintf(out, "pinned: ANOTHER certificate (SHA-256 %s): the primary is refused until this one is checked and pinned\n", zp.CertSHA256)
		case info.Trusted:
			fmt.Fprintln(out, "trusted by the system's roots: no pin needed")
		default:
			fmt.Fprintf(out, "not trusted (%s), not pinned. Check the SHA-256 above on the primary itself, then:\n  espdns %s pin -data %s -sha256 %s\n",
				info.Untrusted, name, *dataDir, info.SHA256)
		}
		return nil
	}
	if info.SHA256 != fp {
		return fmt.Errorf("the zone primary at %s now presents SHA-256 %s, not %s: nothing pinned (espdns %s cert, and check it on the primary)",
			zp.URL, info.SHA256, fp, name)
	}
	if err := settings.SetPrimaryPin(path, zp.URL, fp); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: certificate pinned (SHA-256 %s); another one is refused until it is pinned\n", zp.URL, fp)
	return nil
}
