// Package blocklist turns public blocklists into the hashed sets a node checks names
// against (see "Blocking" in docs/design.md).
package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Canon returns the canonical form of a domain name (lowercase, no trailing dot) and
// whether it is a name a list may block: at least two labels, each 1..63 of [a-z0-9-_],
// at most 253 bytes, and not an IPv4 address.
func Canon(s string) (string, bool) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if len(s) == 0 || len(s) > 253 {
		return "", false
	}
	b := []byte(s)
	labels, start, digitsOnly := 1, 0, true
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 'a' - 'A'
			digitsOnly = false
		case c >= 'a' && c <= 'z', c == '-', c == '_':
			digitsOnly = false
		case c >= '0' && c <= '9':
		case c == '.':
			if i == start || i-start > 63 {
				return "", false
			}
			labels++
			start, digitsOnly = i+1, true
		default:
			return "", false
		}
	}
	if start == len(b) || len(b)-start > 63 || labels < 2 || digitsOnly {
		return "", false // empty last label, too long, single label, or numeric TLD (an IP)
	}
	return string(b), true
}

// Kind is a list's syntax, which also says what an entry blocks.
type Kind int

const (
	Hosts    Kind = iota // "0.0.0.0 name ..." lines: each name exactly
	Domains              // one name per line: exactly that name
	Wildcard             // one name per line, "*." optional: the name and its subdomains
	Adblock              // "||name^" lines: the name and its subdomains; "@@||name^" allows them; other rules skipped
	RPZ                  // a Response Policy Zone (master file): QNAME triggers that block or pass through (parseRPZ)
)

// String is the kind's name, as ParseKind takes it.
func (k Kind) String() string {
	switch k {
	case Hosts:
		return "hosts"
	case Domains:
		return "domains"
	case Wildcard:
		return "wildcard"
	case Adblock:
		return "adblock"
	case RPZ:
		return "rpz"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// MarshalText and UnmarshalText make a kind its name in JSON (a Source in a request).
func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *Kind) UnmarshalText(b []byte) error {
	v, err := ParseKind(string(b))
	if err == nil {
		*k = v
	}
	return err
}

func ParseKind(s string) (Kind, error) {
	switch s {
	case "rpz":
		return RPZ, nil
	case "hosts":
		return Hosts, nil
	case "domains":
		return Domains, nil
	case "wildcard":
		return Wildcard, nil
	case "adblock":
		return Adblock, nil
	}
	return 0, fmt.Errorf("unknown list kind %q (hosts, domains, wildcard, adblock, rpz)", s)
}

// Entry is one name a list blocks, or with Allow, allows; Suffix means its subdomains too.
// An allowlist is parsed like any list (any Kind), with Allow set on its entries.
type Entry struct {
	Name   string
	Suffix bool
	Allow  bool
}

// ParseStats counts what a list held.
type ParseStats struct {
	Lines   int `json:"lines"`
	Entries int `json:"entries"`
	Skipped int `json:"skipped"`
	// An RPZ source's records by what became of them; nil for the other kinds.
	RPZ *RPZStats `json:"rpz,omitempty"`
}

// Parse reads one list. Comments, blank lines and rules the node can't express are
// skipped and counted.
func Parse(r io.Reader, k Kind, emit func(Entry)) (ParseStats, error) {
	if k == RPZ {
		return parseRPZ(r, emit)
	}
	var st ParseStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		st.Lines++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		var names []string
		suffix, allow := false, false
		switch k {
		case Hosts:
			f := strings.Fields(line)
			if len(f) < 2 {
				st.Skipped++
				continue
			}
			names = f[1:]
		case Domains:
			names = []string{line}
		case Wildcard:
			names, suffix = []string{strings.TrimPrefix(line, "*.")}, true
		case Adblock:
			if strings.HasPrefix(line, "@@") {
				line, allow = line[2:], true
			}
			if !strings.HasPrefix(line, "||") || !strings.HasSuffix(line, "^") {
				st.Skipped++
				continue
			}
			names, suffix = []string{line[2 : len(line)-1]}, true
		}
		for _, n := range names {
			c, ok := Canon(n)
			if !ok || c == "localhost.localdomain" {
				st.Skipped++
				continue
			}
			st.Entries++
			emit(Entry{c, suffix, allow})
		}
	}
	return st, sc.Err()
}

// ReadNames reads a file of names, one per line, or Tranco's "rank,name"; # starts a
// comment, and what isn't a name is left out (the CLI's -must-resolve and -popular).
func ReadNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNames(f)
}

// ParseNames is ReadNames on a file's contents.
func ParseNames(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if _, name, ok := strings.Cut(line, ","); ok {
			line = name
		}
		if c, ok := Canon(line); ok {
			out = append(out, c)
		}
	}
	return out, sc.Err()
}
