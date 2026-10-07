package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/dist"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// espdns release build -version 0.0.1 -images DIR -catalog DIR -out DIR [-include FILE ...]
// espdns release sign -dir DIR -pub release.pub          (the release key on standard input)
// espdns release verify -dir DIR -pub release.pub
// espdns release import -dir DIR -pub release.pub -data /data
//
// A release's files (internal/dist, docs/releasing.md). build makes them from the exported
// chip images and the board catalog, with SHA256SUMS, as CI does on a version tag; it uses
// no key. sign signs SHA256SUMS with the release key, read from standard input (the PEM, or
// base64 of it), never an argument or the environment; only a key that is -pub,
// the firmware's built-in release key, is taken. verify checks the signature with -pub and
// every file against SHA256SUMS. import does verify, then puts the release's chip images in
// the data directory (firmware/images), where the builder and the Nodes page's updates
// find them. In the controller's image the public keys are at /keys (release.pub,
// recovery.pub), the ones its firmware's source has.
func cmdRelease(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: espdns release build|sign|verify|import [flags]")
	}
	sub, args := args[0], args[1:]
	fl := flag.NewFlagSet("release "+sub, flag.ContinueOnError)
	switch sub {
	case "build":
		o := dist.Options{}
		fl.StringVar(&o.Version, "version", "", "the version released, the repository's VERSION (required): every chip image must be it")
		fl.StringVar(&o.Images, "images", "", "the exported chip images, <dir>/<image>/image.json (required)")
		fl.StringVar(&o.Catalog, "catalog", "", "the board catalog (boards/; /catalog in the controller's image): a factory image for each (required)")
		fl.StringVar(&o.Out, "out", "", "where the release's files go, missing or empty (required)")
		var inc listFlag
		fl.Var(&inc, "include", "another file the release carries and SHA256SUMS lists (repeatable)")
		if err := parseFlags(fl, args); err != nil {
			return err
		}
		if o.Version == "" || o.Images == "" || o.Catalog == "" || o.Out == "" {
			return errors.New("release build: -version, -images, -catalog and -out are required")
		}
		o.Include = inc
		files, err := dist.Build(o)
		if err != nil {
			return err
		}
		for _, f := range files {
			fmt.Fprintln(stdout, filepath.Join(o.Out, f))
		}
		fmt.Fprintf(stdout, "%d files; not signed: espdns release sign\n", len(files))
		return nil
	case "sign", "verify", "import":
	default:
		return fmt.Errorf("unknown release command %q (build, sign, verify or import)", sub)
	}

	dir := fl.String("dir", "", "the release's files, with its SHA256SUMS (required)")
	pubFile := fl.String("pub", "", "the release public key the firmware is built with (firmware/keys/release.pub; /keys/release.pub in the controller's image) (required)")
	data := ""
	if sub == "import" {
		fl.StringVar(&data, "data", "", "the controller's data directory (/data in Docker) (required)")
	}
	if err := parseFlags(fl, args); err != nil {
		return err
	}
	if *dir == "" || *pubFile == "" || (sub == "import" && data == "") {
		return fmt.Errorf("release %s: -dir and -pub are required%s", sub, map[bool]string{true: ", and -data"}[sub == "import"])
	}
	pub, err := os.ReadFile(*pubFile)
	if err != nil {
		return err
	}
	if len(pub) != 65 || pub[0] != 4 {
		return fmt.Errorf("%s: %d bytes, not a raw P-256 public key (65)", *pubFile, len(pub))
	}
	fp := release.Fingerprint(pub)

	switch sub {
	case "sign":
		if f, ok := stdin.(*os.File); ok {
			if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
				return errors.New("release sign reads the release key from standard input, piped (< release.pem), not typed")
			}
		}
		k, err := readKey("the release key (standard input)", stdin)
		if err != nil {
			return err
		}
		// The whole public key, not its fingerprint (8 bytes of its hash) alone
		if got := release.PublicRaw(k); !bytes.Equal(got, pub) {
			return fmt.Errorf("the key on standard input is %s, not the release key in %s (%s): nodes and users check with that one",
				release.Fingerprint(got), *pubFile, fp)
		}
		if err := dist.Sign(*dir, k); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: signed with the release key %s\n", filepath.Join(*dir, dist.SigFile), fp)
		return nil
	case "verify":
		c, err := dist.Verify(*dir, pub)
		if err != nil {
			return err
		}
		report(stdout, c, fp)
		return nil
	default: // import
		// Under the fleet lock, as every change to the data directory: never under a
		// rollout or a job reading the chip images
		_, end, err := begin(data, "release import", []string{"-dir", *dir}, false)
		if err != nil {
			return err
		}
		images := filepath.Join(data, "firmware", "images")
		done, err := dist.Import(*dir, pub, images)
		end(err)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "signed by the release key %s; chip images imported into %s: %s\n", fp, images, strings.Join(done, ", "))
		return nil
	}
}

func report(w io.Writer, c dist.Checked, fp string) {
	fmt.Fprintf(w, "%s: signed by the release key %s\n", dist.SumsFile, fp)
	for _, f := range c.Files {
		fmt.Fprintf(w, "%s: OK\n", f)
	}
	for _, f := range c.Unlisted {
		fmt.Fprintf(w, "%s: not in %s, not part of the release\n", f, dist.SumsFile)
	}
	fmt.Fprintf(w, "%d files as signed\n", len(c.Files))
}

// parseFlags parses the flags and refuses arguments besides them; -h prints them and exits.
func parseFlags(fl *flag.FlagSet, args []string) error {
	if err := fl.Parse(args); errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	} else if err != nil {
		return err
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %q", fl.Args())
	}
	return nil
}
