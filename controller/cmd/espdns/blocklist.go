package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
)

// cmdBlocklist compiles lists into a node's file: blocklist.Run, the same code a page
// compiles through, with the flags as its Request.
func cmdBlocklist(args []string) error {
	req, asJSON, err := blocklistRequest(args)
	if err != nil {
		return err
	}
	res, err := blocklist.Run(context.Background(), req)
	if asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		printBlocklist(os.Stderr, res)
	}
	return err
}

// blocklistRequest is the flags as a Request (and -json).
func blocklistRequest(args []string) (blocklist.Request, bool, error) {
	var req blocklist.Request
	fs := flag.NewFlagSet("blocklist", flag.ExitOnError)
	var lists, allows listFlag
	fs.Var(&lists, "list", "kind:path or kind:URL of a list to block (hosts, domains, wildcard, adblock, rpz); repeat")
	fs.Var(&allows, "allow", "kind:path or kind:URL of a list to allow; repeat")
	var internal listFlag
	fs.Var(&internal, "internal", "a host (name or IP address) a URL source may be fetched from over plain http or at an inside "+
		"(private, loopback, link-local) address, and only that host (settings.json's internal_sources); repeat. "+
		"Without it a URL source is https from a public address only")
	popular := fs.String("popular", "", "popular names never to block by accident: Tranco CSV (rank,name) or one per line")
	must := fs.String("must-resolve", "", "names the list must not block, one per line")
	fs.IntVar(&req.Bits, "bits", 44, "hash bits")
	fs.IntVar(&req.XorBits, "xor", 10, "xor filter fingerprint bits for the SD tier (0 for none, as for overrides)")
	fs.IntVar(&req.Keys, "keys", 10, "keys to try for one that blocks no popular name")
	fs.StringVar(&req.Out, "out", "", "file to write")
	fs.StringVar(&req.Previous, "previous", "", "the previous build to compare the size with (default: -out, the list's last build; none there: any size)")
	fs.Var(optFlag[float64]{&req.MaxChange, parseFloat}, "max-change", fmt.Sprintf(
		"refuse a build whose blocked or allowed entries (or bytes) change by more than this percentage from the previous build (default %g; 0: any change in size, whatever -min-change)",
		blocklist.DefaultMaxChange))
	fs.Var(optFlag[int]{&req.MinChange, strconv.Atoi}, "min-change", fmt.Sprintf(
		"a change of this many entries or fewer is always taken, whatever its percentage (default %d; 0: no floor)",
		blocklist.DefaultMinChange))
	fs.BoolVar(&req.AcceptChange, "accept-change", false, "take this build even if its size changed by more than -max-change (once)")
	asJSON := fs.Bool("json", false, "print the result as JSON on standard output")
	fs.Parse(args)
	if fs.NArg() > 0 {
		return req, false, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if req.Out == "" || len(lists)+len(allows) == 0 {
		return req, false, fmt.Errorf("need -out and at least one -list or -allow")
	}
	if err := blocklist.CheckLimits(blocklist.Limits(req.MaxChange, req.MinChange)); err != nil {
		return req, false, fmt.Errorf("-max-change, -min-change: %w (-accept-change takes one build whatever its size)", err)
	}
	for _, h := range internal {
		if err := blocklist.CheckHost(h); err != nil {
			return req, false, fmt.Errorf("-internal: %w", err)
		}
		req.Internal = append(req.Internal, h)
	}
	for _, l := range []struct {
		specs listFlag
		allow bool
	}{{lists, false}, {allows, true}} {
		for _, spec := range l.specs {
			s, err := blocklist.ParseSource(spec, l.allow)
			if err != nil {
				return req, false, err
			}
			req.Sources = append(req.Sources, s)
		}
	}
	var err error
	if *popular != "" {
		if req.Popular, err = blocklist.ReadNames(*popular); err != nil {
			return req, false, err
		}
	}
	if *must != "" {
		if req.MustResolve, err = blocklist.ReadNames(*must); err != nil {
			return req, false, err
		}
	}
	return req, *asJSON, nil
}

// optFlag is a flag whose absence is nil (the library's default), so 0 given is 0.
type optFlag[T any] struct {
	p     **T
	parse func(string) (T, error)
}

func (f optFlag[T]) String() string {
	if f.p == nil || *f.p == nil {
		return ""
	}
	return fmt.Sprint(**f.p)
}

func (f optFlag[T]) Set(s string) error {
	v, err := f.parse(s)
	if err != nil {
		return err
	}
	*f.p = &v
	return nil
}

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

// printBlocklist says what a compile did, as far as it got.
func printBlocklist(w io.Writer, r *blocklist.Result) {
	for _, s := range r.Sources {
		what := "block"
		if s.Allow {
			what = "allow"
		}
		fmt.Fprintf(w, "%s (%s): %d entries, %d skipped\n", s.Source, what, s.Entries, s.Skipped)
		if z := s.RPZ; z != nil {
			fmt.Fprintf(w, "  rpz: %d blocked, %d drop (blocked), %d passthru (allowed), %d of them *.name; skipped: "+
				"%d local data, %d tcp-only, %d rpz-ip, %d rpz-client-ip, %d rpz-nsdname, %d rpz-nsip, "+
				"%d outside the zone, %d bad names, %d bad lines, %d $INCLUDE/$GENERATE; %d SOA/NS of the zone\n",
				z.Blocked, z.Drop, z.Allowed, z.Wildcard, z.LocalData, z.TCPOnly, z.IP, z.ClientIP, z.NSDName, z.NSIP,
				z.Outside, z.BadName, z.BadLine, z.Includes, z.Zone)
		}
	}
	if r.File.Size == 0 {
		return
	}
	n := r.BlockedExact + r.BlockedSuffix
	fmt.Fprintf(w, "%d domains blocked (%d exact, %d suffix), %d allowed; %d bytes, %.2f bytes/domain; "+
		"key %d tried, %d hash(es) dropped for popular names\n", n, r.BlockedExact, r.BlockedSuffix,
		r.AllowedExact+r.AllowedSuffix, r.File.Size, float64(r.File.Size)/float64(max(n, 1)), r.Tries, r.Dropped)
	c := r.Change
	switch {
	case c.Previous == "":
		fmt.Fprintf(w, "size: no previous build to compare with\n")
	case c.Old == nil:
		fmt.Fprintf(w, "size: previous build %s replaced (-accept-change): %s\n", c.Previous, strings.Join(c.Over, ", "))
	case len(c.Over) == 0:
		fmt.Fprintf(w, "size: previous build %s: blocked %d → %d, allowed %d → %d, bytes %d → %d: within %g%% or %d entries\n",
			c.Previous, c.Old.Blocked, c.New.Blocked, c.Old.Allowed, c.New.Allowed, c.Old.Bytes, c.New.Bytes, c.MaxChange, c.MinChange)
	case c.Accepted:
		fmt.Fprintf(w, "size: previous build %s: %s: over %g%%, taken (-accept-change)\n", c.Previous, strings.Join(c.Over, ", "), c.MaxChange)
	}
	if r.Written {
		fmt.Fprintf(w, "wrote %s\n", r.Out)
	}
}
