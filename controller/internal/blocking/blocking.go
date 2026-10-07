// Package blocking is a deployment's blocklists as the controller keeps them: what each
// list is compiled from, the local source files, and the compile itself, through the same
// library call (blocklist.Run) and the same request the CLI's flags make:
//
//	blocking/lists.json                  the list definitions (Defs): each list's sources, allow
//	                                     sources, popular and must-resolve names, size-change limits
//	blocking/.history/lists.json.<time>  the versions a save replaced
//	blocking/sources/<file>              local sources: block lists, allow lists, the popular and
//	                                     must-resolve names, and the overrides (overrides.txt,
//	                                     overrides-allow.txt), each edited as text
//	blocking/sources/.history/...        the versions a save replaced or a delete removed
//	lists/<name>.bin                     what a list compiles to, where the rolling push takes it
//
// Every file is written whole or not at all through internal/filestore, the version before
// kept, as the configs and the zones are. A source is kind:file or kind:URL, as the CLI's
// -list and -allow take it; a file is one in blocking/sources, by its name.
package blocking

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/filestore"
	"github.com/skitzo2000/espdns/controller/internal/settings"
)

const (
	Dir        = "blocking"   // in the data directory
	SourcesDir = "sources"    // in Dir
	DefsFile   = "lists.json" // in Dir
	ListsDir   = "lists"      // in the data directory: the compiled files (rolling.ListsDir)
	// OverridesName is the overrides' name: lists/overrides.bin, compiled from
	// OverridesBlock and OverridesAllow (wildcard: one name per line, its subdomains too).
	OverridesName  = "overrides"
	OverridesBlock = "overrides.txt"
	OverridesAllow = "overrides-allow.txt"
	// MaxSource is the most a source file kept here may hold; MaxDefs the definitions.
	MaxSource = 32 << 20
	MaxDefs   = 1 << 20
	// HistoryKeep is how many earlier versions of each file are kept.
	HistoryKeep = 10
	// The build's widths and key tries: the CLI's defaults (espdns blocklist -bits, -xor,
	// -keys), which the page doesn't change; a list's "xor" may (0 for none).
	Bits = 44
	Xor  = 10
	Keys = 10
)

// Path is the blocking directory in dataDir; SourcePath a source file's path; Out a list's
// compiled file.
func Path(dataDir string) string { return filepath.Join(dataDir, Dir) }

func SourcePath(dataDir, name string) string {
	return filepath.Join(dataDir, Dir, SourcesDir, name)
}

func Out(dataDir, name string) string { return filepath.Join(dataDir, ListsDir, name+".bin") }

var (
	sourceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.(txt|zone|rpz|csv|hosts|list)$`)
	nameRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,58}[a-z0-9])?$`)
)

// SourceName refuses a source file name that isn't a plain name in blocking/sources:
// lowercase letters, digits, '.', '_' and '-', ending .txt, .zone, .rpz, .csv, .hosts or .list.
func SourceName(name string) error {
	if len(name) > 100 || !sourceRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%q: a source file is <name>.txt (or .zone, .rpz, .csv, .hosts, .list), with lowercase letters, digits, '.', '_' and '-' only", name)
	}
	return nil
}

// ListName refuses a list name that can't be one: its file is lists/<name>.bin.
func ListName(name string) error {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%q: a list's name is 1 to 60 lowercase letters, digits, '.', '_' and '-' (its file is lists/<name>.bin)", name)
	}
	return nil
}

// Sources is the source files' store.
func Sources(dataDir string) filestore.Store {
	return filestore.Store{Dir: filepath.Join(dataDir, Dir, SourcesDir), Name: SourceName, Max: MaxSource, Keep: HistoryKeep}
}

// DefsStore is the definitions' store (the pending changes write through it).
func DefsStore(dataDir string) filestore.Store { return defsStore(dataDir) }

// defsStore is the definitions' store: one file, checked by Parse.
func defsStore(dataDir string) filestore.Store {
	return filestore.Store{Dir: Path(dataDir), Max: MaxDefs, Keep: 20,
		Name: func(n string) error {
			if n != DefsFile {
				return fmt.Errorf("%q: the definitions are %s", n, DefsFile)
			}
			return nil
		},
		Check: func(_ string, b []byte) error { _, err := Parse(b); return err }}
}

// List is one list's definition.
type List struct {
	Name string `json:"name"`
	// Sources are blocked, Allow allowed: each kind:file (a file in blocking/sources) or
	// kind:URL (https; plain http, or an inside address, only from a host on settings.json's
	// internal_sources), kind hosts, domains, wildcard, adblock or rpz.
	Sources []string `json:"sources,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	// Popular names never blocked by accident (a Tranco CSV or one per line), and names the
	// list must not block at all: files in blocking/sources ("": none).
	Popular     string `json:"popular,omitempty"`
	MustResolve string `json:"must_resolve,omitempty"`
	// Xor is the xor filter's fingerprint bits for the SD tier (nil: 10; 0: none).
	Xor *int `json:"xor,omitempty"`
	// The size-change check (blocklist.Request's): nil is the default, 20% and 100
	// entries; MaxChange 0 refuses any change in size (whatever MinChange), MinChange 0 is
	// no floor.
	MaxChange *float64 `json:"max_change,omitempty"`
	MinChange *int     `json:"min_change,omitempty"`
}

// Defs are the deployment's list definitions (blocking/lists.json).
type Defs struct {
	Lists []List `json:"lists"`
}

// Parse reads and checks lists.json's contents, unknown fields refused.
func Parse(b []byte) (Defs, error) {
	var d Defs
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Defs{}, err
	}
	if dec.More() {
		return Defs{}, errors.New("more than one JSON value")
	}
	if d.Lists == nil {
		d.Lists = []List{}
	}
	return d, d.Check()
}

// Check refuses definitions the compile can't take.
func (d Defs) Check() error {
	seen := map[string]bool{}
	for i, l := range d.Lists {
		if err := l.Check(); err != nil {
			return fmt.Errorf("list %d (%q): %w", i+1, l.Name, err)
		}
		if seen[l.Name] {
			return fmt.Errorf("list %q twice", l.Name)
		}
		seen[l.Name] = true
	}
	return nil
}

// Check refuses a definition the compile can't take (its files needn't be there yet:
// Ready says whether they are).
func (l List) Check() error {
	if err := ListName(l.Name); err != nil {
		return err
	}
	if l.Name == OverridesName {
		return fmt.Errorf("%q is the overrides' (lists/overrides.bin, from %s and %s)", l.Name, OverridesBlock, OverridesAllow)
	}
	if len(l.Sources)+len(l.Allow) == 0 {
		return errors.New("no sources: at least one to block or to allow")
	}
	seen := map[string]bool{}
	for _, specs := range [][]string{l.Sources, l.Allow} {
		for _, spec := range specs {
			if err := CheckSource(spec); err != nil {
				return err
			}
			if seen[spec] {
				return fmt.Errorf("%q twice", spec)
			}
			seen[spec] = true
		}
	}
	for what, f := range map[string]string{"popular": l.Popular, "must_resolve": l.MustResolve} {
		if f == "" {
			continue
		}
		if err := SourceName(f); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	if l.Xor != nil && (*l.Xor < 0 || *l.Xor > 16) {
		return fmt.Errorf("xor: 0 (none) to 16 bits, not %d", *l.Xor)
	}
	if l.MaxChange != nil && (!(*l.MaxChange >= 0) || math.IsInf(*l.MaxChange, 0)) {
		return fmt.Errorf("max_change: a percentage, 0 (no change) or more, not %v", *l.MaxChange)
	}
	if l.MinChange != nil && *l.MinChange < 0 {
		return fmt.Errorf("min_change: 0 (no floor) or more entries, not %d", *l.MinChange)
	}
	return nil
}

// CheckSource refuses a source spec that isn't kind:file (a source file's name) or
// kind:URL (http or https, with a host: plain http is fetched only from a host on the
// internal allowlist, settings.json's internal_sources, which is checked when it is
// fetched).
func CheckSource(spec string) error {
	s, err := blocklist.ParseSource(spec, false)
	if err != nil {
		return err
	}
	if s.IsURL() {
		u, err := url.Parse(s.Path)
		if err != nil || u.Host == "" || strings.ContainsAny(s.Path, " \t\r\n") {
			return fmt.Errorf("%q: not a URL", spec)
		}
		return nil
	}
	if err := SourceName(s.Path); err != nil {
		return fmt.Errorf("%q: a file in %s/%s by its name, or a URL: %w", spec, Dir, SourcesDir, err)
	}
	return nil
}

// RedactURL is a URL with what may be a credential hidden: its user info (a user and
// password, or a token in the user's place) and its query's values (a feed's key often
// goes there). Anything not a URL is as it is.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	if u.User != nil {
		u.User = url.User("xxxxx")
	}
	u.RawQuery = redactQuery(u.RawQuery)
	return u.String()
}

// redactQuery is a URL's query with each value hidden ("" stays "").
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		if k, _, ok := strings.Cut(p, "="); ok {
			parts[i] = k + "=xxxxx"
		} else if p != "" {
			parts[i] = "xxxxx"
		}
	}
	return strings.Join(parts, "&")
}

// Redactor hides the credentials of the list's URLs (RedactURL) in text that may name them:
// a compile job's log, its command, its result and its error, which are readable without a
// login while no password is set, and kept on disk. Each URL is replaced as it is written in
// the definition and as Go's HTTP client names it in an error (the password already hidden).
func (l List) Redactor() *strings.Replacer {
	var pairs []string
	for _, specs := range [][]string{l.Sources, l.Allow} {
		for _, spec := range specs {
			s, err := blocklist.ParseSource(spec, false)
			if err != nil || !s.IsURL() {
				continue
			}
			red := RedactURL(s.Path)
			pairs = append(pairs, s.Path, red)
			if u, err := url.Parse(s.Path); err == nil {
				if r := u.Redacted(); r != s.Path {
					pairs = append(pairs, r, red)
				}
				if u.RawQuery != "" {
					// The query alone, wherever else the URL is written another way.
					pairs = append(pairs, "?"+u.RawQuery, "?"+redactQuery(u.RawQuery))
				}
			}
		}
	}
	return strings.NewReplacer(pairs...)
}

// Lookup is the list of that name: the overrides, or one of the definitions.
func (d Defs) Lookup(dataDir, name string) (List, bool) {
	if name == OverridesName {
		return Overrides(dataDir), true
	}
	for _, l := range d.Lists {
		if l.Name == name {
			return l, true
		}
	}
	return List{}, false
}

// Overrides is the overrides as a list: overrides.txt blocked and overrides-allow.txt
// allowed (wildcard), the ones there, no xor filter (the RAM tier), as
//
//	espdns blocklist -list wildcard:overrides.txt -allow wildcard:overrides-allow.txt -xor 0 -out overrides.bin
func Overrides(dataDir string) List {
	zero := 0
	l := List{Name: OverridesName, Xor: &zero}
	if _, err := os.Stat(SourcePath(dataDir, OverridesBlock)); err == nil {
		l.Sources = []string{"wildcard:" + OverridesBlock}
	}
	if _, err := os.Stat(SourcePath(dataDir, OverridesAllow)); err == nil {
		l.Allow = []string{"wildcard:" + OverridesAllow}
	}
	return l
}

// IsOverrides says whether the list is the overrides (pushed as kind overrides).
func (l List) IsOverrides() bool { return l.Name == OverridesName }

// Files are the source files the list reads (not its URLs), each once.
func (l List) Files() []string {
	var out []string
	add := func(f string) {
		for _, o := range out {
			if o == f {
				return
			}
		}
		out = append(out, f)
	}
	for _, specs := range [][]string{l.Sources, l.Allow} {
		for _, spec := range specs {
			if s, err := blocklist.ParseSource(spec, false); err == nil && !s.IsURL() {
				add(s.Path)
			}
		}
	}
	for _, f := range []string{l.Popular, l.MustResolve} {
		if f != "" {
			add(f)
		}
	}
	return out
}

// Uses says whether the list reads the source file.
func (l List) Uses(file string) bool {
	for _, f := range l.Files() {
		if f == file {
			return true
		}
	}
	return false
}

// Ready refuses a list whose files aren't there to compile it from.
func (l List) Ready(dataDir string) error {
	if len(l.Sources)+len(l.Allow) == 0 {
		if l.IsOverrides() {
			return fmt.Errorf("no overrides yet: write %s (names to block) or %s (names to allow) first", OverridesBlock, OverridesAllow)
		}
		return errors.New("no sources")
	}
	var missing []string
	for _, f := range l.Files() {
		fi, err := os.Stat(SourcePath(dataDir, f))
		if errors.Is(err, fs.ErrNotExist) {
			missing = append(missing, f)
		} else if err != nil {
			return err
		} else if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: not a regular file", SourcePath(dataDir, f))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no such source file in %s/%s: %s", Dir, SourcesDir, strings.Join(missing, ", "))
	}
	return nil
}

func (l List) xor() int {
	if l.Xor != nil {
		return *l.Xor
	}
	return Xor
}

// Internal is the internal allowlist as this list's compile takes it: the entries of
// settings.json's internal_sources that a URL source of the list is fetched from (none
// when it has no URL source; settings.json is read only then).
func (l List) Internal(dataDir string) ([]string, error) {
	var hosts []string
	for _, spec := range append(slices.Clone(l.Sources), l.Allow...) {
		if s, err := blocklist.ParseSource(spec, false); err == nil && s.IsURL() {
			hosts = append(hosts, s.Host())
		}
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	st, err := settings.Load(settings.Path(dataDir))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, h := range st.InternalSources {
		if slices.ContainsFunc(hosts, func(x string) bool { return blocklist.SameHost(x, h) }) {
			out = append(out, h)
		}
	}
	return out, nil
}

// Request is the compile of the list, as blocklist.Run takes it: what Args gives the CLI
// becomes the same request (the parity test). The popular and must-resolve names are read
// now, as the CLI reads them, and the internal allowlist (Internal) from settings.json.
func (l List) Request(dataDir string, accept bool) (blocklist.Request, error) {
	r := blocklist.Request{Bits: Bits, XorBits: l.xor(), Keys: Keys, Out: Out(dataDir, l.Name),
		MaxChange: l.MaxChange, MinChange: l.MinChange, AcceptChange: accept}
	var err error
	if r.Internal, err = l.Internal(dataDir); err != nil {
		return r, err
	}
	for _, src := range []struct {
		specs []string
		allow bool
	}{{l.Sources, false}, {l.Allow, true}} {
		for _, spec := range src.specs {
			s, err := blocklist.ParseSource(l.resolve(dataDir, spec), src.allow)
			if err != nil {
				return r, err
			}
			r.Sources = append(r.Sources, s)
		}
	}
	if l.Popular != "" {
		if r.Popular, err = blocklist.ReadNames(SourcePath(dataDir, l.Popular)); err != nil {
			return r, err
		}
	}
	if l.MustResolve != "" {
		if r.MustResolve, err = blocklist.ReadNames(SourcePath(dataDir, l.MustResolve)); err != nil {
			return r, err
		}
	}
	return r, nil
}

// resolve is a spec with its file as a path in dataDir (a URL as it is).
func (l List) resolve(dataDir, spec string) string {
	s, err := blocklist.ParseSource(spec, false)
	if err != nil || s.IsURL() {
		return spec
	}
	return s.Kind.String() + ":" + SourcePath(dataDir, s.Path)
}

// Args are the espdns blocklist flags for the same compile, its files in dataDir (in the
// image, /data): what the page shows as the CLI's command, and what the parity test runs
// through the CLI's flag parsing.
func (l List) Args(dataDir string, accept bool) []string {
	var a []string
	for _, spec := range l.Sources {
		a = append(a, "-list", l.resolve(dataDir, spec))
	}
	for _, spec := range l.Allow {
		a = append(a, "-allow", l.resolve(dataDir, spec))
	}
	if l.Popular != "" {
		a = append(a, "-popular", SourcePath(dataDir, l.Popular))
	}
	if l.MustResolve != "" {
		a = append(a, "-must-resolve", SourcePath(dataDir, l.MustResolve))
	}
	if l.Xor != nil {
		a = append(a, "-xor", strconv.Itoa(*l.Xor))
	}
	if l.MaxChange != nil {
		a = append(a, "-max-change", strconv.FormatFloat(*l.MaxChange, 'g', -1, 64))
	}
	if l.MinChange != nil {
		a = append(a, "-min-change", strconv.Itoa(*l.MinChange))
	}
	internal, _ := l.Internal(dataDir) // settings.json unreadable: Request says so
	for _, h := range internal {
		a = append(a, "-internal", h)
	}
	a = append(a, "-out", Out(dataDir, l.Name))
	if accept {
		a = append(a, "-accept-change")
	}
	return a
}

// Command is Args as a command line to read (each argument quoted when it needs to be).
func (l List) Command(dataDir string, accept bool) string {
	parts := []string{"espdns", "blocklist"}
	for _, a := range l.Args(dataDir, accept) {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`&;|<>()*?[]#~!{}") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// ---- the files ----------------------------------------------------------------------------

// Load reads the definitions and their hash ("" and none when there is no file yet).
func Load(dataDir string) (Defs, string, error) {
	f, err := defsStore(dataDir).Read(DefsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Defs{Lists: []List{}}, "", nil
	}
	if err != nil {
		return Defs{Lists: []List{}}, "", err
	}
	d, err := Parse(f.Text)
	if err != nil {
		return Defs{Lists: []List{}}, f.Hash, fmt.Errorf("%s: %w", filepath.Join(Path(dataDir), DefsFile), err)
	}
	return d, f.Hash, nil
}

// Save writes the definitions over the version expect names (its hash; "" for the first),
// the version before kept. It returns the new hash.
func Save(dataDir string, d Defs, expect string) (string, error) {
	if d.Lists == nil {
		d.Lists = []List{}
	}
	if err := d.Check(); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := defsStore(dataDir).Save(DefsFile, b, expect); err != nil {
		return "", err
	}
	return filestore.Hash(b), nil
}

// History is the definitions' kept versions, newest first.
func History(dataDir string) ([]filestore.Version, error) {
	return defsStore(dataDir).History(DefsFile)
}

// ReadVersion is a kept version of the definitions.
func ReadVersion(dataDir, file string) ([]byte, error) {
	return defsStore(dataDir).ReadVersion(DefsFile, file)
}
