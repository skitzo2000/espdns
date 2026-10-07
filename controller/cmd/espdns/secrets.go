package main

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/skitzo2000/espdns/controller/internal/keys"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Secrets from the environment at run time (exported, or put there by a password
// manager), none written to disk. In Docker (docs/rollout.md) the release key comes on
// standard input instead (-key -), so it is never in the container's environment; the token comes by name.
const (
	// envReleaseKey is the release signing key, the PEM file base64-encoded, or the PEM
	// itself. Used when -key is left at its default; an explicit -key file and -recovery always read the file.
	envReleaseKey = "ESPDNS_RELEASE_KEY"
	// The zone primary's API token: $ESPDNS_PRIMARY_TOKEN, else the variable -primary-token-env
	// names (the Makefile's PRIMARY_TOKEN_ENV); -primary-token-file wins over both.
	envPrimaryToken = "ESPDNS_PRIMARY_TOKEN"
)

// keyStdin as -key reads the key from standard input: the PEM, or base64 of it. The
// fleet-* Docker runs pipe it in this way (docs/rollout.md), so the key is never in a
// container's environment, an argument or a file.
const keyStdin = "-"

// loadReleaseKey is the signing key: standard input with -key -, else $ESPDNS_RELEASE_KEY
// when it is set and -key is the default, else the file.
func loadReleaseKey(path string, recovery bool) (*ecdsa.PrivateKey, error) {
	if path == keyStdin {
		return readKey("-key - (standard input)", os.Stdin)
	}
	v := os.Getenv(envReleaseKey)
	if strings.TrimSpace(v) == "" || recovery || path != defaultKey {
		return release.LoadKey(path)
	}
	return parseKeyText("$"+envReleaseKey, v)
}

// readKey reads a key (PEM, or base64 of one) to the end of r.
func readKey(name string, r io.Reader) (*ecdsa.PrivateKey, error) {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return parseKeyText(name, string(b))
}

// parseKeyText parses a PEM key, or base64 of one. Errors say name, never the value.
func parseKeyText(name, v string) (*ecdsa.PrivateKey, error) {
	return keys.Parse(name, []byte(v))
}

// primaryToken is the zone primary's API token: from file if one is named, else the
// environment ($ESPDNS_PRIMARY_TOKEN, then $<env> when env is named).
func primaryToken(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	names := []string{envPrimaryToken}
	if env != "" {
		names = append(names, env)
	}
	for _, e := range names {
		if t := strings.TrimSpace(os.Getenv(e)); t != "" {
			return t, nil
		}
	}
	return "", nil
}
