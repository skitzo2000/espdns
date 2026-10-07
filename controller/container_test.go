// The controller's container setup (compose.yaml,
// .dockerignore) for the hardening it must keep (controller/README.md, Running it): no
// capabilities, no new privileges, a read-only root with a small /tmp, memory and process
// limits, a non-root user; and a build context that is an allowlist, so no data directory,
// whatever it is called, gets into an image. (In pins_test's package: one per directory.)
package pins_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func lines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestComposeHardening(t *testing.T) {
	compose := strings.Join(lines(t, "compose.yaml"), "\n")
	for what, re := range map[string]string{
		"every capability dropped":                 `(?m)^cap_drop: \[ALL\]$`,
		"no new privileges":                        `(?m)^security_opt: \["no-new-privileges:true"\]$`,
		"a read-only root filesystem":              `(?m)^read_only: true$`,
		"a small /tmp in memory, noexec":           `(?m)^- /tmp:size=\d+m,mode=1777,noexec,nosuid,nodev$`,
		"a memory limit":                           `(?m)^mem_limit: \$\{ESPDNS_MEM_LIMIT:-\d+[mg]\}$`,
		"Go's soft limit under it":                 `(?m)^GOMEMLIMIT: \$\{ESPDNS_GOMEMLIMIT:-\d+MiB\}$`,
		"a process limit":                          `(?m)^pids_limit: \$\{ESPDNS_PIDS_LIMIT:-\d+\}$`,
		"the data directory's owner, required":     `(?m)^user: "\$\{ESPDNS_UID:\?[^}]*\}:\$\{ESPDNS_GID:\?[^}]*\}"$`,
		"the data directory never made by compose": `(?m)^create_host_path: false$`,
	} {
		if !regexp.MustCompile(re).MatchString(compose) {
			t.Errorf("compose.yaml: %s: no line matching %s", what, re)
		}
	}
	for _, bad := range []string{"privileged: true", "cap_add", "docker.sock", "/var/run/docker"} {
		if strings.Contains(compose, bad) {
			t.Errorf("compose.yaml: %s", bad)
		}
	}
	// The memory limit and Go's soft limit, as .env.example documents them, are the defaults
	m := regexp.MustCompile(`mem_limit: \$\{ESPDNS_MEM_LIMIT:-(\d+)g\}`).FindStringSubmatch(compose)
	g := regexp.MustCompile(`GOMEMLIMIT: \$\{ESPDNS_GOMEMLIMIT:-(\d+)MiB\}`).FindStringSubmatch(compose)
	if m == nil || g == nil {
		t.Fatal("compose.yaml: no limits to compare")
	}
	env := read(t, ".env.example") // commented out there, as defaults are
	for _, want := range []string{"#ESPDNS_MEM_LIMIT=" + m[1] + "g", "#ESPDNS_GOMEMLIMIT=" + g[1] + "MiB", "#ESPDNS_PIDS_LIMIT="} {
		if !strings.Contains(env, want) {
			t.Errorf(".env.example: no %s (compose.yaml's default)", want)
		}
	}
	mem, _ := strconv.Atoi(m[1])
	gomem, _ := strconv.Atoi(g[1])
	if mem *= 1024; gomem >= mem || gomem < mem*8/10 {
		t.Errorf("GOMEMLIMIT %d MiB: not about nine tenths of the %d MiB limit", gomem, mem)
	}
}

// The build context is an allowlist: everything left out, then only what the build needs.
func TestDockerignoreAllowlist(t *testing.T) {
	ign := lines(t, ".dockerignore")
	if len(ign) == 0 || ign[0] != "*" {
		t.Fatalf(".dockerignore: first pattern %q, want * (an allowlist)", ign)
	}
	allowed := map[string]bool{}
	for _, l := range ign[1:] {
		if p, ok := strings.CutPrefix(l, "!"); ok {
			allowed[strings.TrimSuffix(p, "/")] = true
		}
	}
	for _, need := range []string{"go.mod", "go.sum", "cmd", "internal", "web"} {
		if !allowed[need] {
			t.Errorf(".dockerignore: %s isn't let in (the Dockerfile's build needs it)", need)
		}
	}
	for p := range allowed {
		if p == "data" || strings.Contains(p, ".env") || strings.Contains(p, "local.mk") || strings.Contains(p, "*") {
			t.Errorf(".dockerignore lets %s in", p)
		}
	}
	for _, never := range []string{"**/*.pem", "**/auth.json"} {
		if !strings.Contains(strings.Join(ign, "\n"), never) {
			t.Errorf(".dockerignore: no %s", never)
		}
	}
}

// The binaries carry the repository's VERSION (internal/version): make build and the image
// both link it in, at the package's path, and the image's build gets it from the repository's
// top, a context whose .dockerignore lets in VERSION only.
func TestVersionLinked(t *testing.T) {
	const x = "-X github.com/skitzo2000/espdns/controller/internal/version.Version="
	if _, err := os.Stat("internal/version/version.go"); err != nil {
		t.Fatal(err)
	}
	mk := read(t, "Makefile")
	if !strings.Contains(mk, x+"$(shell cat $(CURDIR)/../VERSION)") {
		t.Errorf("Makefile: no %s<VERSION>", x)
	}
	for _, bin := range []string{"espdns-controller", "espdns"} {
		if !regexp.MustCompile(`(?m)^\tCGO_ENABLED=0 go build -trimpath -ldflags='\$\(VERSION_LDFLAGS\)' -o ` + bin + ` `).MatchString(mk) {
			t.Errorf("Makefile: %s built without the version", bin)
		}
	}
	df := read(t, "Dockerfile")
	if !strings.Contains(df, "COPY --from=version VERSION /VERSION") {
		t.Error("Dockerfile: VERSION not copied from the version context")
	}
	if n := strings.Count(df, x+"$v\""); n != 2 {
		t.Errorf("Dockerfile: %d builds link the version, want 2", n)
	}
	if !regexp.MustCompile(`(?m)^version: \.\.$`).MatchString(strings.Join(lines(t, "compose.yaml"), "\n")) {
		t.Error("compose.yaml: no version: .. build context")
	}
	if ign := lines(t, "../.dockerignore"); len(ign) != 2 || ign[0] != "*" || ign[1] != "!VERSION" {
		t.Errorf("../.dockerignore: %q, want * and !VERSION only", ign)
	}
}

// The image carries the firmware's public keys at /keys (espdns release verify checks a
// release with /keys/release.pub), from firmware/keys, a context whose .dockerignore lets in
// the two public keys only: never a private key, whatever is put there.
func TestPublicKeysInImage(t *testing.T) {
	if !strings.Contains(read(t, "Dockerfile"), "COPY --from=keys release.pub recovery.pub /keys/") {
		t.Error("Dockerfile: the public keys not copied from the keys context to /keys")
	}
	if !regexp.MustCompile(`(?m)^keys: \.\./firmware/keys$`).MatchString(strings.Join(lines(t, "compose.yaml"), "\n")) {
		t.Error("compose.yaml: no keys: ../firmware/keys build context")
	}
	if ign := lines(t, "../firmware/keys/.dockerignore"); len(ign) != 3 || ign[0] != "*" || ign[1] != "!release.pub" || ign[2] != "!recovery.pub" {
		t.Errorf("../firmware/keys/.dockerignore: %q, want *, !release.pub and !recovery.pub only", ign)
	}
	for _, k := range []string{"release.pub", "recovery.pub"} {
		if b, err := os.ReadFile("../firmware/keys/" + k); err != nil || len(b) != 65 || b[0] != 4 {
			t.Errorf("firmware/keys/%s: not a raw P-256 public key (%v)", k, err)
		}
	}
}
