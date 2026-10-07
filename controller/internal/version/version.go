// Package version is espDNS's version: the controller's own, and the semantic versions the
// firmware and the controller are numbered by (docs/plan.md, Phase F, "Versions"; 0.0.x while
// in alpha).
//
// One file says it: VERSION at the top of the repository, which the firmware's build reads
// (firmware/CMakeLists.txt: the app descriptor's version, as /status and the image header
// say it) and the controller's builds link in (controller/Makefile, controller/Dockerfile:
// -ldflags -X .../internal/version.Version=<VERSION>). scripts/bump-version.sh changes it.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is this controller's version, set at link time from the repository's VERSION
// file. A build without it (go run, go test) is Dev.
var Version = Dev

// Dev is the version of a build that wasn't given one.
const Dev = "dev"

// Semver is a version as MAJOR.MINOR.PATCH, each a whole number without leading zeros, of
// at most MaxDigits digits. The project numbers its releases this way only: no pre-release
// or build suffix.
type Semver struct{ Major, Minor, Patch uint64 }

// MaxDigits is the most digits in each number of a version, here, in firmware/version.cmake
// and in scripts/bump-version.sh alike, so that a version one of them takes the others
// take too, and the longest (29 bytes) fits the app descriptor's 32.
const MaxDigits = 9

// Parse reads a version ("0.0.4"). Anything else, a commit as a build from before versions
// says it ("3fbae0a") or "v0.0.4", is an error.
func Parse(s string) (Semver, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Semver{}, fmt.Errorf("version %q: not MAJOR.MINOR.PATCH", s)
	}
	var n [3]uint64
	for i, p := range parts {
		if p == "" || len(p) > MaxDigits || (len(p) > 1 && p[0] == '0') || strings.TrimLeft(p, "0123456789") != "" {
			return Semver{}, fmt.Errorf("version %q: not MAJOR.MINOR.PATCH (whole numbers of at most %d digits, no leading zeros)", s, MaxDigits)
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return Semver{}, fmt.Errorf("version %q: %v", s, err)
		}
		n[i] = v
	}
	return Semver{n[0], n[1], n[2]}, nil
}

func (v Semver) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare is below 0 when v is older than w, 0 the same version, above 0 newer.
func (v Semver) Compare(w Semver) int {
	for _, d := range [][2]uint64{{v.Major, w.Major}, {v.Minor, w.Minor}, {v.Patch, w.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}
