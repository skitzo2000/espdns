package blocklist

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// The size-change check's defaults (Request.MaxChange, Request.MinChange).
const (
	DefaultMaxChange = 20.0 // percent
	DefaultMinChange = 100  // entries
)

// MaxFetch is the most a source fetched from a URL may be.
const MaxFetch = 512 << 20

// maxFetch is MaxFetch, smaller in a test.
var maxFetch int64 = MaxFetch

// Source is one list the compiler reads: its syntax, a file or a URL (https; plain http
// only from a host on the internal allowlist, fetch.go), and whether it allows what it
// names (an allowlist) instead of blocking it.
type Source struct {
	Kind  Kind   `json:"kind"`
	Path  string `json:"path"`
	Allow bool   `json:"allow"`
}

// ParseSource reads the CLI's kind:path (or kind:URL) form. A plain http URL is refused
// when it is fetched unless its host is on the internal allowlist (fetch.go).
func ParseSource(spec string, allow bool) (Source, error) {
	kind, path, ok := strings.Cut(spec, ":")
	if !ok || path == "" {
		return Source{}, fmt.Errorf("%q: want kind:path or kind:URL", spec)
	}
	k, err := ParseKind(kind)
	if err != nil {
		return Source{}, err
	}
	return Source{Kind: k, Path: path, Allow: allow}, nil
}

// Host is a URL source's host ("" for a file).
func (s Source) Host() string {
	if !s.IsURL() {
		return ""
	}
	u, err := url.Parse(s.Path)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// String is the source in its kind:path form.
func (s Source) String() string { return s.Kind.String() + ":" + s.Path }

// IsURL says whether the source is a URL (fetched over https, or plain http from a host on
// the internal allowlist; never a file's name).
func (s Source) IsURL() bool {
	return strings.HasPrefix(s.Path, "http://") || strings.HasPrefix(s.Path, "https://")
}

// Request is one compile: the sources, the build's choices, where the file goes and the
// size-change check against the previous build. The CLI's flags and a page's form both
// become one (Run).
type Request struct {
	Sources []Source
	// Popular names never blocked by accident; the must-resolve list, never blocked at all
	// (BuildOptions).
	Popular, MustResolve []string
	Bits                 int // hash bits (0: 44)
	XorBits              int // xor fingerprint bits for the SD tier (0: none, as for overrides)
	Keys                 int // keys to try (0: 1)
	// Out is the file to write; "" writes nothing (the result says what it would be).
	Out string
	// Previous is the build to compare with; "": Out, the list's last build, and none
	// there: any size is accepted. A Previous given must be there.
	Previous string
	// The size-change check: a build is refused if its blocked or allowed entries change by
	// more than MaxChange percent from the previous build and by more than MinChange
	// entries, or (built with the same widths) its bytes by more than MaxChange percent.
	// nil: the default (DefaultMaxChange, DefaultMinChange). MaxChange 0 refuses any
	// change in size (the floor doesn't apply then; a build of as many other names is the
	// same size, so taken); MinChange 0 is no floor. AcceptChange takes a refused build once.
	MaxChange    *float64
	MinChange    *int
	AcceptChange bool
	// Internal is the internal allowlist (settings.json's internal_sources, the CLI's
	// -internal): the hosts a URL source may be fetched from over plain http or at an
	// inside address (fetch.go).
	Internal []string
	// Fetch: how URL sources are fetched besides the rules (fetch.go); nil in use, set by
	// a test.
	Fetch *Fetch
	Rand  io.Reader // nil: crypto/rand
	// Logf, if set, is told each step as it starts and ends (a job's live progress).
	Logf func(format string, args ...any)
}

func (r Request) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// SourceResult is what one source gave.
type SourceResult struct {
	Source string `json:"source"` // kind:path
	Allow  bool   `json:"allow"`
	ParseStats
}

// Size is a build's size as the size-change check compares it.
type Size struct {
	Blocked int `json:"blocked"` // hashes in the two block tables
	Allowed int `json:"allowed"` // hashes in the two allow tables
	Bytes   int `json:"bytes"`
	Bits    int `json:"bits"`
	XorBits int `json:"xor_bits"`
}

// SizeChange is the size-change check's outcome.
type SizeChange struct {
	Previous  string  `json:"previous,omitempty"` // the build compared with; "" none (accepted)
	Old       *Size   `json:"old,omitempty"`
	New       Size    `json:"new"`
	MaxChange float64 `json:"max_change"` // percent
	MinChange int     `json:"min_change"`
	// Over names each measure that changed by more than allowed ("blocked 1000 → 600
	// (-40.0%)"); empty when within the limits.
	Over []string `json:"over,omitempty"`
	// Accepted: over the limits, taken by Request.AcceptChange.
	Accepted bool `json:"accepted,omitempty"`
	// Refused: over the limits and not accepted; nothing was written.
	Refused bool `json:"refused,omitempty"`
}

// Result is a compile's outcome, as data: the CLI prints it, a page shows it.
type Result struct {
	Sources       []SourceResult `json:"sources"`
	Compile       CompileStats   `json:"compile"`
	BlockedExact  int            `json:"blocked_exact"`
	BlockedSuffix int            `json:"blocked_suffix"`
	AllowedExact  int            `json:"allowed_exact"`
	AllowedSuffix int            `json:"allowed_suffix"`
	Tries         int            `json:"tries"`   // keys tried
	Dropped       int            `json:"dropped"` // block hashes dropped for popular names
	File          FileStats      `json:"file"`
	Change        SizeChange     `json:"change"`
	Out           string         `json:"out,omitempty"`
	Written       bool           `json:"written"`
}

// SizeChangeError is the refusal of a build whose size changed too much.
type SizeChangeError struct{ Change SizeChange }

func (e *SizeChangeError) Error() string {
	return fmt.Sprintf("refused: the build changes by more than %s%% from the previous build %s: %s; nothing written "+
		"(if the change is meant, -accept-change, make ACCEPT_CHANGE=1, takes it once)", fmtPct(e.Change.MaxChange),
		e.Change.Previous, strings.Join(e.Change.Over, ", "))
}

// Run compiles a request's sources into a list file, checks it against the previous build
// and writes it to Out (whole: a new file renamed over the old). The result is filled as
// far as the run got, also on an error; a size-change refusal is a *SizeChangeError.
func Run(ctx context.Context, req Request) (*Result, error) {
	res := &Result{Out: req.Out}
	if len(req.Sources) == 0 {
		return res, errors.New("no sources")
	}
	if err := CheckLimits(Limits(req.MaxChange, req.MinChange)); err != nil {
		return res, err
	}
	var entries []Entry
	for _, s := range req.Sources {
		sr := SourceResult{Source: s.String(), Allow: s.Allow}
		what := "block"
		if s.Allow {
			what = "allow"
		}
		req.logf("%s (%s): reading", sr.Source, what)
		st, err := readSource(ctx, req.Fetch, req.Internal, s, func(e Entry) {
			e.Allow = e.Allow || s.Allow
			entries = append(entries, e)
		})
		sr.ParseStats = st
		res.Sources = append(res.Sources, sr)
		if err != nil {
			return res, fmt.Errorf("%s: %w", s.Path, err)
		}
		req.logf("%s (%s): %d entries, %d skipped", sr.Source, what, st.Entries, st.Skipped)
	}
	c := Compile(entries)
	res.Compile = c.Stats
	res.BlockedExact, res.BlockedSuffix = len(c.Exact), len(c.Suffix)
	res.AllowedExact, res.AllowedSuffix = len(c.AllowExact), len(c.AllowSuffix)
	o := BuildOptions{Bits: req.Bits, XorBits: req.XorBits, Keys: req.Keys, Popular: req.Popular,
		MustResolve: req.MustResolve, Rand: req.Rand}
	if o.Bits == 0 {
		o.Bits = 44
	}
	req.logf("%d entries merged: %d blocked, %d allowed; building (%d-bit hashes, %d-bit xor)",
		c.Stats.In, len(c.Exact)+len(c.Suffix), len(c.AllowExact)+len(c.AllowSuffix), o.Bits, o.XorBits)
	file, st, err := Build(c, o)
	res.Tries, res.Dropped, res.File = st.Tries, st.Dropped, st.File
	if err != nil {
		return res, err
	}
	newSize, _ := ReadSize(file)
	prev := req.Previous
	if prev == "" {
		prev = req.Out
	} else if _, err := os.Stat(prev); err != nil {
		// Only Out's absence is a first build; a previous build named and not there is a
		// mistake, not a reason to take any size.
		return res, fmt.Errorf("the previous build: %w", err)
	}
	maxChange, minChange := Limits(req.MaxChange, req.MinChange)
	res.Change, err = CheckSize(prev, newSize, maxChange, minChange, req.AcceptChange)
	if err != nil {
		return res, err
	}
	if res.Change.Refused {
		return res, &SizeChangeError{res.Change}
	}
	if req.Out == "" {
		return res, nil
	}
	// Stopped while it built (the build doesn't look): nothing written.
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if err := writeWhole(req.Out, file); err != nil {
		return res, err
	}
	res.Written = true
	req.logf("wrote %s: %d bytes", req.Out, len(file))
	return res, nil
}

// readSource parses one source, from its file or URL (Fetch.get).
func readSource(ctx context.Context, f *Fetch, internal []string, s Source, emit func(Entry)) (ParseStats, error) {
	if !s.IsURL() {
		f, err := os.Open(s.Path)
		if err != nil {
			return ParseStats{}, err
		}
		defer f.Close()
		return Parse(f, s.Kind, emit)
	}
	resp, err := f.get(ctx, s.Path, internal)
	if err != nil {
		return ParseStats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ParseStats{}, fmt.Errorf("HTTP %s", resp.Status)
	}
	lr := &io.LimitedReader{R: resp.Body, N: maxFetch + 1}
	st, err := Parse(lr, s.Kind, emit)
	if lr.N == 0 {
		err = fmt.Errorf("more than %d MiB", maxFetch>>20)
	}
	return st, err
}

// ReadSize reads a list file's size from its header (the start of the file is enough for
// the counts; Bytes is len(b)).
func ReadSize(b []byte) (Size, error) {
	if len(b) < FileHeader || string(b[:8]) != FileMagic {
		return Size{}, errors.New("not a blocklist file (espdns blocklist ... -out)")
	}
	if b[8] != FileVersion {
		return Size{}, fmt.Errorf("blocklist file version %d, not %d", b[8], FileVersion)
	}
	s := Size{Bytes: len(b), Bits: int(b[9]), XorBits: int(b[10])}
	for t := range NTables {
		n := int(binary.LittleEndian.Uint32(b[32+32*t:]))
		if t == TExact || t == TSuffix {
			s.Blocked += n
		} else {
			s.Allowed += n
		}
	}
	return s, nil
}

// ReadSizeFile is ReadSize on a file, read only as far as its header.
func ReadSizeFile(path string) (Size, error) {
	f, err := os.Open(path)
	if err != nil {
		return Size{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Size{}, err
	}
	hdr := make([]byte, FileHeader)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return Size{}, fmt.Errorf("%s: not a blocklist file (espdns blocklist ... -out)", path)
	}
	s, err := ReadSize(hdr)
	if err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	s.Bytes = int(fi.Size())
	return s, nil
}

// Limits is the size-change check's two limits with the defaults for the unset (nil) ones.
func Limits(maxChange *float64, minChange *int) (float64, int) {
	mx, mn := DefaultMaxChange, DefaultMinChange
	if maxChange != nil {
		mx = *maxChange
	}
	if minChange != nil {
		mn = *minChange
	}
	return mx, mn
}

// CheckLimits says whether the size-change limits are ones the check can use: a
// percentage of 0 or more and a floor of 0 or more entries.
func CheckLimits(maxChange float64, minChange int) error {
	if !(maxChange >= 0) || math.IsInf(maxChange, 0) { // NaN too
		return fmt.Errorf("the size change allowed is %v%%: a percentage, 0 (no change) or more", maxChange)
	}
	if minChange < 0 {
		return fmt.Errorf("the size change floor is %d entries: 0 (no floor) or more", minChange)
	}
	return nil
}

// CheckSize compares a new build's size with the previous build at prev (none there, or
// prev "": accepted). The limits are as given (Limits fills in the defaults): maxChange 0
// refuses any change in size, whatever the floor; minChange 0 is no floor. A previous file
// that isn't a list is an error unless accept.
func CheckSize(prev string, n Size, maxChange float64, minChange int, accept bool) (SizeChange, error) {
	sc := SizeChange{New: n, MaxChange: maxChange, MinChange: minChange}
	if err := CheckLimits(maxChange, minChange); err != nil {
		return sc, err
	}
	if maxChange == 0 { // no change: no floor either
		minChange, sc.MinChange = 0, 0
	}
	if prev == "" {
		return sc, nil
	}
	old, err := ReadSizeFile(prev)
	if errors.Is(err, fs.ErrNotExist) {
		return sc, nil
	}
	sc.Previous = prev
	if err != nil {
		if accept {
			sc.Over, sc.Accepted = []string{err.Error()}, true
			return sc, nil
		}
		return sc, fmt.Errorf("the previous build: %w (not replaced; -accept-change replaces it)", err)
	}
	sc.Old = &old
	entries := func(what string, o, nw int) {
		d := nw - o
		if abs(d) > minChange && pct(o, nw) > maxChange {
			sc.Over = append(sc.Over, fmt.Sprintf("%s %d → %d (%s)", what, o, nw, change(o, nw)))
		}
	}
	entries("blocked", old.Blocked, n.Blocked)
	entries("allowed", old.Allowed, n.Allowed)
	if old.Bits == n.Bits && old.XorBits == n.XorBits &&
		abs(n.Blocked+n.Allowed-old.Blocked-old.Allowed) > minChange && pct(old.Bytes, n.Bytes) > maxChange {
		sc.Over = append(sc.Over, fmt.Sprintf("bytes %d → %d (%s)", old.Bytes, n.Bytes, change(old.Bytes, n.Bytes)))
	}
	if len(sc.Over) > 0 {
		sc.Accepted, sc.Refused = accept, !accept
	}
	return sc, nil
}

// pct is the change from o to n in percent of o (infinite from 0).
func pct(o, n int) float64 {
	if o == 0 {
		if n == 0 {
			return 0
		}
		return math.Inf(1)
	}
	return math.Abs(float64(n-o)) * 100 / float64(o)
}

// change is the signed change, "+12.5%", or "from none".
func change(o, n int) string {
	if o == 0 {
		return "from none"
	}
	return fmt.Sprintf("%+.1f%%", float64(n-o)*100/float64(o))
}

func fmtPct(p float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", p), "0"), ".")
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// writeWhole writes a file whole: a temporary file beside it, renamed over it.
func writeWhole(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // on disk before it replaces the old one
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(secfile.FileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
