package version

import (
	"os"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for s, want := range map[string]Semver{"0.0.1": {0, 0, 1}, "0.0.12": {0, 0, 12}, "1.20.300": {1, 20, 300},
		"999999999.999999999.999999999": {999999999, 999999999, 999999999}} {
		v, err := Parse(s)
		if err != nil || v != want || v.String() != s {
			t.Errorf("%q: %+v %v", s, v, err)
		}
	}
	for _, s := range []string{"", "3fbae0a", "bff81c1-dirty", "v0.0.1", "0.0", "0.0.1.2", "0.01.1", "0.0.-1", "0.0.1-rc1",
		"0.0.1+abc", " 0.0.1", "0..1", "0.0.99999999999", "0.0.1000000000", "4294967295.0.0", "dev"} {
		if v, err := Parse(s); err == nil {
			t.Errorf("%q: parsed as %v", s, v)
		}
	}
}

func TestCompare(t *testing.T) {
	order := []string{"0.0.1", "0.0.2", "0.0.10", "0.1.0", "0.1.9", "1.0.0", "1.0.1", "2.0.0"}
	for i, a := range order {
		for j, b := range order {
			va, _ := Parse(a)
			vb, _ := Parse(b)
			c := va.Compare(vb)
			if (i < j && c >= 0) || (i == j && c != 0) || (i > j && c <= 0) {
				t.Errorf("%s vs %s: %d", a, b, c)
			}
		}
	}
}

// The repository's VERSION, the one source of the version, is one version on one line.
func TestRepoVersion(t *testing.T) {
	b, err := os.ReadFile("../../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := strings.CutSuffix(string(b), "\n")
	if !ok || strings.Contains(s, "\n") {
		t.Fatalf("VERSION %q: one line, ending in a newline", b)
	}
	if _, err := Parse(s); err != nil {
		t.Error(err)
	}
}
