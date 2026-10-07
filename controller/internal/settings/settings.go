// Package settings is the deployment's settings file, <data>/settings.json: the one file
// the controller and the espdns CLI both read (docs/rollout.md, Settings). The controller
// polls its nodes and the CLI counts them as peers; both count its DNS peers for the
// last-healthy-node rule. In Docker the data directory is /data, mounted from the host
// (controller/data), so the CLI's fleet targets and the controller read the same file.
package settings

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/skitzo2000/espdns/controller/internal/blocklist"
	"github.com/skitzo2000/espdns/controller/internal/primary"
	"github.com/skitzo2000/espdns/controller/internal/secfile"
)

// File is the settings file's name in the data directory.
const File = "settings.json"

// Settings is settings.json. Every field is optional; unknown fields are refused, so a
// misspelt one (a DNS peer that would silently not count) is an error, not a default.
type Settings struct {
	// Nodes are node addresses (host, or host:port for an HTTP port other than 80): the
	// controller polls them even if mDNS doesn't find them, and with -mdns 0 (every fleet
	// target that changes a node) they are the only nodes the CLI counts as peers. A host
	// given by name must be one the node answers to (the name in its node config, or its
	// .local name): a node refuses a request whose Host names anything else (421, against
	// DNS rebinding; firmware/main/httpguard.h). An address always works.
	Nodes []string `json:"nodes,omitempty"`
	// DNSPeers are resolvers clients use besides the nodes (the zone primary, 192.0.2.254, or
	// addr:port for a DNS port other than 53): each counts as one answering peer while it
	// resolves a forwarded name and answers its zones' SOA authoritatively (the CLI's
	// -dns-peer).
	DNSPeers []string `json:"dns_peers,omitempty"`
	// DNSPeerZones are the zones the DNS peers must answer for (-dns-peer-zone); empty: the
	// secondary zones of the node about to be changed.
	DNSPeerZones []string `json:"dns_peer_zones,omitempty"`
	// Canary is the node the controller's Push page changes first unless you choose
	// another (the Makefile's CANARY); one of Nodes. Empty: the first node changed.
	Canary string `json:"canary,omitempty"`
	// NoDHCP are the networks with no DHCP server (IPv4, each as its network, a.b.c.0/nn): a
	// node there is never given a config on DHCP, by adoption from the CLI or the
	// controller's Adopt page. Empty (the default): none, and DHCP is offered wherever the
	// node is, with its reservation.
	NoDHCP []string `json:"no_dhcp,omitempty"`
	// Primary is the zone primary the nodes copy their secondary zones from, as adoption
	// and the controller's Zone primary view reach it (internal/primary):
	// {"kind": "manual"} for any primary, its transfer and NOTIFY lists changed by hand;
	// {"kind": "technitium", "url": "https://<host>:53443"} for Technitium's API (https
	// only), with the token (keys/primary.token), and "cert_sha256", the fingerprint of
	// its certificate pinned when it is self-signed (set by confirming it: SetPrimaryPin).
	// Absent: none set up, treated as manual.
	Primary *primary.Config `json:"primary,omitempty"`
	// InternalSources is the internal allowlist: the hosts (a name or an IP address, no
	// scheme or port) a blocklist URL source may be fetched from although it is inside
	// (a private, loopback or link-local address) or over plain http; such a fetch goes to
	// that host only (internal/blocklist, fetch.go). Empty (the default): sources are https
	// from public addresses only.
	InternalSources []string `json:"internal_sources,omitempty"`
}

// Path is the settings file in dataDir.
func Path(dataDir string) string { return filepath.Join(dataDir, File) }

// Load reads the settings file at path; none (the zero Settings) if there is no file.
func Load(path string) (Settings, error) {
	var s Settings
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if s, err = Parse(b); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Parse reads and checks settings.json's contents.
func Parse(b []byte) (Settings, error) {
	var s Settings
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Settings{}, err
	}
	if d.More() {
		return Settings{}, errors.New("more than one JSON value")
	}
	if err := s.Check(); err != nil {
		return s, err
	}
	return s, nil
}

// FieldError is a setting refused: Field is its name in settings.json ("nodes", "primary").
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

func refuse(field, format string, a ...any) error {
	return &FieldError{Field: field, Err: fmt.Errorf(format, a...)}
}

// Check refuses an empty or repeated entry, and an address that isn't one. The error is a
// *FieldError. A zone primary at a plain http address is let through
// (primary.Config.CheckSaved: paused, never reached), so a settings.json written before
// https was required still loads; POST /api/settings refuses one (primary.Config.Check).
func (s Settings) Check() error {
	for _, l := range []struct {
		name string
		v    []string
		addr bool
	}{{"nodes", s.Nodes, true}, {"dns_peers", s.DNSPeers, true}, {"dns_peer_zones", s.DNSPeerZones, false}} {
		for i, v := range l.v {
			switch {
			case strings.TrimSpace(v) != v || v == "" || strings.ContainsAny(v, " \t/"):
				return refuse(l.name, "%q is not a %s", v, map[bool]string{true: "host or host:port", false: "zone name"}[l.addr])
			case slices.Contains(l.v[:i], v):
				return refuse(l.name, "%s twice", v)
			}
			if l.addr && strings.Contains(v, ":") {
				if _, port, err := net.SplitHostPort(v); err != nil || port == "" {
					return refuse(l.name, "%q is not a host or host:port", v)
				}
			}
		}
	}
	for i, v := range s.NoDHCP {
		p, err := netip.ParsePrefix(v)
		switch {
		case err != nil || !p.Addr().Is4():
			return refuse("no_dhcp", "%q is not an IPv4 network with its prefix length (a.b.c.0/nn)", v)
		case p.Masked() != p:
			return refuse("no_dhcp", "%s is not a network (%s is)", v, p.Masked())
		case slices.Contains(s.NoDHCP[:i], v):
			return refuse("no_dhcp", "%s twice", v)
		}
	}
	for i, h := range s.InternalSources {
		if err := blocklist.CheckHost(h); err != nil {
			return refuse("internal_sources", "%v", err)
		}
		if blocklist.InternalHost(h, s.InternalSources[:i]) {
			return refuse("internal_sources", "%s twice", h)
		}
	}
	if s.Canary != "" && !slices.Contains(s.Nodes, s.Canary) {
		return refuse("canary", "%s is not one of the nodes", s.Canary)
	}
	if s.Primary != nil {
		// A plain http address already in the file is let through (the primary paused, the
		// controller still starting); a save through POST /api/settings refuses one.
		if err := s.Primary.CheckSaved(); err != nil {
			return &FieldError{Field: "primary", Err: err}
		}
	}
	return nil
}

// NoDHCPAt is the network in no_dhcp that addr is on, if any: a node there gets a static
// address, never DHCP.
func (s Settings) NoDHCPAt(addr netip.Addr) (netip.Prefix, bool) {
	for _, v := range s.NoDHCP {
		if p, err := netip.ParsePrefix(v); err == nil && p.Contains(addr.Unmap()) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

// ZonePrimary is the zone primary set up ("primary"); the zero Config when there is none
// (adoption then treats it as manual).
func (s Settings) ZonePrimary() primary.Config {
	if s.Primary != nil {
		return *s.Primary
	}
	return primary.Config{}
}

// mu orders this process's writes of the file: an edit from the browser (SaveIf) and an
// adoption's (AddNode, MoveNode) each read the file and write it whole, one at a time.
var mu sync.Mutex

// ErrChanged: the file is no longer the version an edit was made on.
var ErrChanged = errors.New("settings.json changed since it was read: read it again")

// Version is the file's version: the SHA-256 of its bytes, "" when there is none.
func Version(b []byte, exists bool) string {
	if !exists {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Read is the settings file at path with its version (Version) and whether it exists. A
// file that doesn't parse gives its version and the error, so it can still be replaced.
func Read(path string) (s Settings, version string, exists bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, "", false, nil
	}
	if err != nil {
		return s, "", false, err
	}
	version = Version(b, true)
	if s, err = Parse(b); err != nil {
		return Settings{}, version, true, fmt.Errorf("%s: %w", path, err)
	}
	return s, version, true, nil
}

// SaveIf writes s to path (Save) if the file is still the version an edit was made on
// (Version; "" for none), else ErrChanged. before and after, each if not nil, run with the
// version checked and no other write of the file in between (what must change with it: the
// zone primary's token): before ahead of the write, its error stopping it; after once the
// file is written, its error returned with the file saved.
func SaveIf(path, version string, s Settings, before, after func() error) error {
	if err := s.Check(); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	b, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if Version(b, exists) != version {
		return ErrChanged
	}
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	if err := Save(path, s); err != nil {
		return err
	}
	if after != nil {
		return after()
	}
	return nil
}

// ErrNoPrimaryAPI: settings.json names no zone primary reached over an API, or another
// address than the one whose certificate was confirmed.
var ErrNoPrimaryAPI = errors.New("settings.json names no zone primary at that API address")

// SetPrimaryPin pins the zone primary's certificate (its SHA-256 fingerprint, as
// primary.Fingerprint writes it), or takes the pin away (pin ""), in the settings file,
// written whole; only while its "primary" is still the API at url (the address the
// certificate was read from), else ErrNoPrimaryAPI. The caller has shown the fingerprint
// and had it confirmed (the confirm step: trust on first confirm).
func SetPrimaryPin(path, url, pin string) error {
	mu.Lock()
	defer mu.Unlock()
	s, err := Load(path)
	if err != nil {
		return err
	}
	if s.Primary == nil || s.Primary.URL == "" || s.Primary.URL != url {
		return ErrNoPrimaryAPI
	}
	p := *s.Primary
	p.CertSHA256 = pin
	s.Primary = &p
	return Save(path, s)
}

// MoveNode changes a node's address in the settings file's nodes, in its place (and as the
// canary, if it is the canary), written whole; false if from isn't there. If to is listed
// already, from is only taken out.
func MoveNode(path, from, to string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()
	s, err := Load(path)
	if err != nil {
		return false, err
	}
	i := slices.Index(s.Nodes, from)
	if i < 0 {
		return false, nil
	}
	if slices.Contains(s.Nodes, to) {
		s.Nodes = slices.Delete(s.Nodes, i, i+1)
	} else {
		s.Nodes[i] = to
	}
	if s.Canary == from {
		s.Canary = to
	}
	if err := Save(path, s); err != nil {
		return false, err
	}
	return true, nil
}

// AddNode adds addr to the settings file's nodes, as the last one, and writes it whole
// (Save); false if it is there already. The file is read again here, so an edit made since
// it was last read is kept, and refused as a whole if it no longer parses.
func AddNode(path, addr string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()
	s, err := Load(path)
	if err != nil {
		return false, err
	}
	if slices.Contains(s.Nodes, addr) {
		return false, nil
	}
	s.Nodes = append(s.Nodes, addr)
	if err := Save(path, s); err != nil {
		return false, err
	}
	return true, nil
}

// Save writes the settings to path, whole or not at all (a temporary file renamed over it).
func Save(path string, s Settings) error {
	if err := s.Check(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".settings-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
