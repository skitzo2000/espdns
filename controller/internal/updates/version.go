package updates

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skitzo2000/espdns/controller/internal/version"
)

// Versions. The plan shows updates as versions ("0.0.1 → 0.0.4"), with the build hash only
// under Details. A build's version is what its app descriptor says: the repository's VERSION
// when it was built (docs/plan.md, Phase F, "Versions"; internal/version), MAJOR.MINOR.PATCH.
// Builds are ordered by their versions; two builds of one version (a fix built again before
// the version moved on) by when they were built, the same build known by its ELF hash. A
// build whose version isn't one (firmware from before versions, whose descriptor says a
// commit) can't be ordered against another.
//
// Of, Compare and Later are the one place that knows this.

// Scheme is how Compare orders versions, for the API: by version, the build time breaking
// a tie.
const Scheme = "version"

// Version is one firmware as the pages show it.
type Version struct {
	// Text is what the pages show ("0.0.4").
	Text string `json:"version"`
	// Build is the ELF's SHA-256 (its first 8 bytes, hex, as /status says it): the same
	// build is the same firmware. Shown under Details only.
	Build string `json:"build"`
	// Built is when it was built, as its descriptor says it ("Oct  7 2026 12:00:00").
	Built string `json:"built,omitempty"`
	sem   version.Semver
	ok    bool // sem was read: Text is a version
	at    time.Time
}

// builtLayout is the descriptor's date and time (__DATE__ " " __TIME__), as
// release.ParseAppDesc and the node's /status give them.
const builtLayout = "Jan _2 2006 15:04:05"

// maxText is the most of a version shown (the descriptor holds 32 bytes).
const maxText = 32

// Clean is text a node or a build says, as the pages and a change's summary show it: one
// line, no control characters or invalid UTF-8, at most max bytes (cut at a character).
func Clean(s string, max int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "")))
	for len(s) > max {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

// Of is the version of a firmware from its app descriptor's version, build time and ELF
// hash (release.AppDesc's, or /status "version", "built", "elf_sha256").
func Of(text, built, elf string) Version {
	text = Clean(text, maxText)
	v := Version{Text: text, Build: strings.ToLower(strings.TrimSpace(elf)), Built: strings.TrimSpace(built)}
	if v.Text == "" {
		v.Text = v.Build
	}
	if sem, err := version.Parse(text); err == nil {
		v.sem, v.ok = sem, true
	}
	if t, err := time.Parse(builtLayout, v.Built); err == nil {
		v.at = t
	}
	return v
}

// Compare orders two versions: below 0 when a is older than b, 0 the same build, above 0
// newer. Two builds are ordered by their versions, and two of the same version by their
// build times. ok is false when they can't be ordered: either has no version, or two builds
// of one version, either without a build time read, or both built at the same second.
func Compare(a, b Version) (c int, ok bool) {
	if a.Build != "" && a.Build == b.Build {
		return 0, true
	}
	if !a.ok || !b.ok {
		return 0, false
	}
	if c := a.sem.Compare(b.sem); c != 0 {
		return c, true
	}
	if a.at.IsZero() || b.at.IsZero() {
		return 0, false
	}
	return a.at.Compare(b.at), !a.at.Equal(b.at)
}

// Later says whether a is the newer pick of two builds for a node: newer by Compare, or,
// where they can't be ordered, a has a version and b none, or of one version, a has a build
// time and b none.
func Later(a, b Version) bool {
	if c, ok := Compare(a, b); ok {
		return c > 0
	}
	if a.ok != b.ok {
		return a.ok
	}
	return a.ok && a.sem == b.sem && !a.at.IsZero() && b.at.IsZero()
}
