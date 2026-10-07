package primary

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"
)

// The zone primary's API is reached over https only: the API token is in every request,
// and over plain http it would cross the network in clear (docs/plan.md, Security review,
// #69). The primary's certificate is verified, always: against the system's roots, or, for
// a primary with its own (self-signed) certificate, against that one certificate, pinned
// by its SHA-256 fingerprint (Config.CertSHA256). A pin is set only by confirming the
// fingerprint the primary presents (Presented, then settings.SetPrimaryPin: the API's
// POST /api/primary/certificate, the CLI's espdns primary pin): trust on first confirm.
// A primary that then presents another certificate is refused (CertError) and nothing is
// sent to it until its new certificate is confirmed. Verification is never switched off.

// apiTimeout bounds one call to the primary's API.
const apiTimeout = 10 * time.Second

// systemRoots are the roots a certificate not pinned is verified against: nil, the
// system's (a test sets its own).
var systemRoots *x509.CertPool

// Fingerprint is a certificate's SHA-256 fingerprint as settings.json keeps it: the hash of
// its DER bytes, 64 lowercase hex digits.
func Fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

// ParseFingerprint reads a SHA-256 fingerprint as people copy it (upper or lower case,
// with or without colons or spaces between the bytes) into Fingerprint's form.
func ParseFingerprint(s string) (string, error) {
	f := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(f); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("%q is not a SHA-256 fingerprint (64 hex digits, colons allowed)", s)
	}
	return f, nil
}

// checkPin refuses a pin that isn't in Fingerprint's form (settings.json's "cert_sha256").
func checkPin(s string) error {
	if f, err := ParseFingerprint(s); err != nil || f != s {
		return fmt.Errorf("%q is not a SHA-256 fingerprint in 64 lowercase hex digits (as the confirm step writes it)", s)
	}
	return nil
}

// CertError is a primary refused for its certificate: one the system's roots don't
// verify, with nothing pinned (Pinned ""), or one other than the certificate pinned.
// Presented is the fingerprint of the certificate it presented.
type CertError struct {
	Host      string
	Presented string
	Pinned    string
	Err       error // why it isn't trusted (not pinned), if known
}

func (e *CertError) Error() string {
	if e.Pinned == "" {
		why := ""
		if e.Err != nil {
			why = " (" + e.Err.Error() + ")"
		}
		return fmt.Sprintf("the zone primary at %s presents a certificate this controller doesn't trust%s, SHA-256 %s: "+
			"nothing was sent to it. If it is the primary's own (self-signed) certificate, check that fingerprint on the "+
			"primary and pin it (POST /api/primary/certificate, or espdns primary pin -sha256 <it>)", e.Host, why, e.Presented)
	}
	return fmt.Sprintf("the zone primary at %s presents a certificate other than the one pinned (SHA-256 %s, pinned %s): "+
		"refused, nothing was sent to it. If its certificate was renewed, check the new fingerprint on the primary and "+
		"pin it again (POST /api/primary/certificate, or espdns primary pin -sha256 <it>)", e.Host, e.Presented, e.Pinned)
}

func (e *CertError) Unwrap() error { return e.Err }

// CertInfo is a certificate a primary presents, as the confirm step shows it.
type CertInfo struct {
	SHA256    string    `json:"sha256"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Names     []string  `json:"names"` // its DNS names and IP addresses (subjectAltName)
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Trusted: the system's roots verify it for the address's host (no pin needed);
	// Untrusted says why not.
	Trusted   bool   `json:"trusted"`
	Untrusted string `json:"untrusted,omitempty"`
}

func infoOf(c *x509.Certificate) CertInfo {
	i := CertInfo{SHA256: Fingerprint(c), Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		Names: append([]string{}, c.DNSNames...), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC()}
	for _, ip := range c.IPAddresses {
		i.Names = append(i.Names, ip.String())
	}
	return i
}

// Presented is the certificate the https API address raw presents now, read in a TLS
// handshake (nothing else is sent: no request, no token), and whether the system's roots
// verify it. It is what the confirm step shows before a pin is set.
func Presented(ctx context.Context, raw string) (CertInfo, error) {
	u, err := httpsURL(raw)
	if err != nil {
		return CertInfo{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	conn, err := handshake(ctx, hostPort(u), &tls.Config{ServerName: u.Hostname(), RootCAs: systemRoots, MinVersion: tls.VersionTLS12})
	if err == nil {
		defer conn.Close()
		i := infoOf(conn.ConnectionState().PeerCertificates[0])
		i.Trusted = true
		return i, nil
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) && len(cve.UnverifiedCertificates) > 0 {
		i := infoOf(cve.UnverifiedCertificates[0])
		i.Untrusted = cve.Err.Error()
		return i, nil
	}
	return CertInfo{}, fmt.Errorf("the zone primary at %s: %w", u.Host, err)
}

// httpsURL parses an API address that must be https.
func httpsURL(raw string) (*neturl.URL, error) {
	u, err := neturl.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%q is not an https address", raw)
	}
	return u, nil
}

// hostPort is the URL's host with its port (443 when it names none).
func hostPort(u *neturl.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

// handshake connects to addr and completes a TLS handshake with c.
func handshake(ctx context.Context, addr string, c *tls.Config) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: apiTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, c)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// Client is the HTTP client a driver reaches c's API with: https only, the certificate
// verified against the system's roots, or, with c.CertSHA256, the pinned certificate
// only (CertError otherwise). No proxy: the connection goes to the primary itself.
func Client(c Config) *http.Client {
	p := &pinned{pin: c.CertSHA256}
	t := &http.Transport{
		Proxy:               nil,
		DialTLSContext:      p.dialTLS,
		DialContext:         func(context.Context, string, string) (net.Conn, error) { return nil, errPlainAPI },
		TLSHandshakeTimeout: apiTimeout,
		ForceAttemptHTTP2:   false,
		// A connection per request: a handful per adoption or view, each checked against
		// the pin, and none left idle for the primary to close under a POST (not retried)
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: t, Timeout: apiTimeout}
}

// errPlainAPI: a request over plain http (the transport refuses it before connecting).
var errPlainAPI = errors.New("the zone primary's API is reached over https only: the token is never sent over plain http")

// pinned dials the primary over TLS: verified against the system's roots, or, with pin, the
// pinned certificate only.
type pinned struct {
	pin  string
	mu   sync.Mutex
	leaf *x509.Certificate // the pinned certificate, once seen
}

func (p *pinned) dialTLS(ctx context.Context, _, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	system := &tls.Config{ServerName: host, RootCAs: systemRoots, MinVersion: tls.VersionTLS12}
	if p.pin == "" {
		conn, err := handshake(ctx, addr, system)
		var cve *tls.CertificateVerificationError
		if errors.As(err, &cve) && len(cve.UnverifiedCertificates) > 0 {
			return nil, &CertError{Host: host, Presented: Fingerprint(cve.UnverifiedCertificates[0]), Err: cve.Err}
		}
		return conn, err
	}
	p.mu.Lock()
	leaf := p.leaf
	p.mu.Unlock()
	if leaf == nil {
		// The pinned certificate isn't known yet, only its fingerprint: read the one the
		// primary presents (verified by the system's roots, or not), and go on only if it is
		// the one pinned.
		conn, err := handshake(ctx, addr, system)
		var got *x509.Certificate
		var cve *tls.CertificateVerificationError
		switch {
		case err == nil:
			got = conn.ConnectionState().PeerCertificates[0]
		case errors.As(err, &cve) && len(cve.UnverifiedCertificates) > 0:
			got = cve.UnverifiedCertificates[0]
		default:
			return nil, err
		}
		if fp := Fingerprint(got); fp != p.pin {
			if conn != nil {
				conn.Close()
			}
			return nil, &CertError{Host: host, Presented: fp, Pinned: p.pin}
		}
		p.mu.Lock()
		p.leaf = got
		p.mu.Unlock()
		if conn != nil { // the system's roots verify it, and it is the one pinned
			return conn, nil
		}
		leaf = got
	}
	// Verified against the pinned certificate alone (it is its own root), under a name it
	// carries: the pin, not the name, says it is the primary's. Then its fingerprint is
	// checked again, so a certificate the pinned one signed isn't taken for it.
	name := nameIn(leaf, host)
	if name == "" {
		return nil, fmt.Errorf("the zone primary at %s: its pinned certificate names no host or address "+
			"(no subjectAltName), so it can't be verified: give the primary a certificate that names it, and pin that", host)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	cfg := &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if fp := Fingerprint(cs.PeerCertificates[0]); fp != p.pin {
				return &CertError{Host: host, Presented: fp, Pinned: p.pin}
			}
			return nil
		}}
	conn, err := handshake(ctx, addr, cfg)
	if err == nil {
		return conn, nil
	}
	p.mu.Lock()
	p.leaf = nil // read again next time
	p.mu.Unlock()
	var ce *CertError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &ce):
		return nil, ce
	case errors.As(err, &cve) && len(cve.UnverifiedCertificates) > 0:
		if fp := Fingerprint(cve.UnverifiedCertificates[0]); fp != p.pin {
			return nil, &CertError{Host: host, Presented: fp, Pinned: p.pin}
		}
		return nil, fmt.Errorf("the zone primary at %s: its pinned certificate (SHA-256 %s) doesn't verify: %v "+
			"(an expired one: renew it on the primary and pin the new one)", host, p.pin, cve.Err)
	}
	return nil, err
}

// nameIn is a name the certificate is valid for: host itself if it is, else its first DNS
// name (a wildcard's with a label put in) or IP address; "" when it names none.
func nameIn(c *x509.Certificate, host string) string {
	if c.VerifyHostname(host) == nil {
		return host
	}
	for _, n := range c.DNSNames {
		if strings.HasPrefix(n, "*.") {
			n = "pinned" + n[1:]
		}
		if c.VerifyHostname(n) == nil {
			return n
		}
	}
	for _, ip := range c.IPAddresses {
		return ip.String()
	}
	return ""
}
