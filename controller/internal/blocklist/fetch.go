package blocklist

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"
)

// A source fetched from a URL is fetched over https only, from a public address only
// (docs/plan.md, Security review, #69): the controller runs on the LAN, often with host
// networking, and a list's URL (or a redirect it follows) must not make it a way to reach
// the controller itself, its nodes or anything else inside. Each address is checked as it
// is connected to, after the name is resolved, so a name that resolves to a public address
// once and an inside one the next time (DNS rebinding), and every redirect, are checked
// too.
//
// A list server inside your network is fetched only if its host is on the internal
// allowlist (settings.json's "internal_sources", Request.Internal): a source whose host is
// on it may be plain http and may resolve to an inside address (private, loopback,
// link-local), and that fetch goes to that host only: a redirect elsewhere is refused, and
// the connection check still runs for every connection, so only a connection for the host
// allowed may reach an inside address (another name, or a redirect, rebound to one is
// refused). A list kept on the controller itself is a file source.

// fetchTimeout bounds a whole fetch.
const fetchTimeout = 5 * time.Minute

// maxRedirects is how many redirects a fetch follows (as Go's default client).
const maxRedirects = 10

// Fetch is how URL sources are fetched besides the rules above, for a test: the TLS
// config (trusting a test server's certificate) and the exact addresses (a test server on
// loopback) connected to although not public. Request.Fetch nil: none, the system's roots.
type Fetch struct {
	TLS   *tls.Config
	Allow []netip.AddrPort
}

// notPublic are the IPv4 and IPv6 networks a fetch never connects to besides what netip
// names (loopback, private, link-local, multicast, unspecified): this network, shared
// address space (carrier-grade NAT, also Tailscale's), IETF protocol assignments,
// benchmarking, reserved and broadcast, deprecated site-local IPv6, NAT64's local-use
// prefix, and the IPv4-compatible and IPv4-translated forms of an inside address. An
// address through NAT64's well-known prefix or 6to4 is checked for the IPv4 one it carries
// (embedded4).
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10), // shared address space (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"), // 255.255.255.255 too
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("fec0::/10"),
}

// publicAddr refuses an address a fetch must not connect to.
func publicAddr(a netip.Addr) error {
	a = a.Unmap()
	inside := !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified()
	for _, p := range notPublic {
		inside = inside || p.Contains(a)
	}
	if v4, ok := embedded4(a); ok && !inside {
		if err := publicAddr(v4); err != nil {
			return &insideError{a}
		}
	}
	if inside {
		return &insideError{a}
	}
	return nil
}

// Prefixes whose IPv6 addresses carry an IPv4 one a gateway connects on to: NAT64's
// well-known prefix (the IPv4 address in the last 32 bits; with DNS64, a name's A record
// comes back as one) and 6to4 (in bits 16 to 47).
var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

// embedded4 is the IPv4 address an IPv6 one reaches through a NAT64 or 6to4 gateway: that
// one must be public too.
func embedded4(a netip.Addr) (netip.Addr, bool) {
	b := a.As16()
	switch {
	case !a.Is6():
		return netip.Addr{}, false
	case nat64.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixTo4.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// insideError is a connection refused to an address that isn't public.
type insideError struct{ addr netip.Addr }

func (e *insideError) Error() string {
	return fmt.Sprintf("refused to connect to %s: not a public address (a list server inside your network: "+
		"put its host in settings.json's internal_sources; a list kept here: a file source)", e.addr)
}

// guard is the dialer's check of each address it is about to connect to: the resolved
// one, so a name can't stand in for an inside address. inside: the connection is for the
// host on the internal allowlist this fetch is for, which may be at any address.
func (f *Fetch) guard(inside bool) func(_, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return fmt.Errorf("refused to connect to %q: %w", address, err)
		}
		if inside || (f != nil && slices.Contains(f.Allow, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))) {
			return nil
		}
		return publicAddr(ap.Addr())
	}
}

// client is the client a source is fetched with: every connection checked (guard), no
// proxy (the proxy would make the connection, unchecked), and every redirect checked
// (redirects). internal is the source's host when it is on the internal allowlist (""
// otherwise): only a connection for that host may reach an inside address, and its
// redirects stay on it. One per fetch.
func (f *Fetch) client(internal string) *http.Client {
	var tc *tls.Config
	if f != nil && f.TLS != nil {
		tc = f.TLS.Clone()
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		d := &net.Dialer{Timeout: 30 * time.Second, Control: f.guard(internal != "" && SameHost(host, internal))}
		return d.DialContext(ctx, network, addr)
	}
	t := &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     tc,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true, // one fetch, then the client is dropped: nothing left idle
	}
	return &http.Client{Transport: t, Timeout: fetchTimeout, CheckRedirect: redirects(internal)}
}

// redirects follows at most maxRedirects, never from https to plain http, and: for a
// source on the internal allowlist (internal, its host), only to that same host; for any
// other, only to https (to a public address: its connection is checked as any other).
func redirects(internal string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		u := req.URL
		switch {
		case internal != "" && !SameHost(u.Hostname(), internal):
			return &redirectError{u.Scheme, u.Host, "a source on the internal allowlist is fetched from its own host only"}
		case u.Scheme != "https" && (internal == "" || u.Scheme != "http"):
			return &redirectError{u.Scheme, u.Host, "a source is fetched over https only"}
		case u.Scheme != "https" && via[len(via)-1].URL.Scheme == "https":
			return &redirectError{u.Scheme, u.Host, "a downgrade from https"}
		case len(via) >= maxRedirects:
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		return nil
	}
}

// redirectError is a redirect refused, and why. It names the target's scheme and host
// only: its path and query may hold a key.
type redirectError struct{ scheme, host, why string }

func (e *redirectError) Error() string {
	return fmt.Sprintf("refused a redirect to %s://%s (%s)", e.scheme, e.host, e.why)
}

// get GETs a source's URL. internal is the internal allowlist (Request.Internal). A
// refusal comes back as itself, not as Go's error naming the whole URL (its query may
// hold a key).
func (f *Fetch) get(ctx context.Context, u string, internal []string) (*http.Response, error) {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	host := ""
	if InternalHost(hr.URL.Hostname(), internal) {
		host = hr.URL.Hostname()
	}
	switch {
	case hr.URL.Scheme == "http" && host == "":
		return nil, errPlainHTTP
	case hr.URL.Scheme != "https" && hr.URL.Scheme != "http":
		return nil, fmt.Errorf("a source URL is https (or http to a host on the internal allowlist), not %s", hr.URL.Scheme)
	}
	resp, err := f.client(host).Do(hr)
	if re := (*redirectError)(nil); errors.As(err, &re) {
		return nil, re
	}
	if ie := (*insideError)(nil); errors.As(err, &ie) {
		return nil, ie
	}
	return resp, err
}

// errPlainHTTP is a source URL over plain http whose host isn't on the internal allowlist:
// anyone on the path could change the list.
var errPlainHTTP = errors.New("a source URL over plain http is refused (anyone on the path could change the list): " +
	"use https, or, for a list server inside your network, put its host in settings.json's internal_sources")

// InternalHost says whether host is on the internal allowlist: the same host (SameHost) as
// one of its entries.
func InternalHost(host string, internal []string) bool {
	return slices.ContainsFunc(internal, func(h string) bool { return SameHost(host, h) })
}

// SameHost says whether two hosts are the same: the same IP address (in any of its forms),
// or the same name, whatever its case or a trailing dot.
func SameHost(a, b string) bool {
	a, b = strings.TrimSuffix(strings.Trim(a, "[]"), "."), strings.TrimSuffix(strings.Trim(b, "[]"), ".")
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA == nil || errB == nil {
		return errA == nil && errB == nil && x.Unmap() == y.Unmap()
	}
	return a != "" && strings.EqualFold(a, b)
}

// CheckHost refuses an internal allowlist entry that isn't a host: an IP address, or a DNS
// name (letters, digits, hyphens, dots; no scheme, port, path or wildcard).
func CheckHost(h string) error {
	if _, err := netip.ParseAddr(h); err == nil {
		if strings.Contains(h, "%") {
			return fmt.Errorf("%q: an address with a zone is not a host to list", h)
		}
		return nil
	}
	name := strings.TrimSuffix(h, ".")
	if name == "" || len(name) > 253 {
		return fmt.Errorf("%q is not a host name or an IP address", h)
	}
	for _, l := range strings.Split(name, ".") {
		ok := l != "" && len(l) <= 63 && l[0] != '-' && l[len(l)-1] != '-'
		for _, c := range l {
			ok = ok && (c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
		}
		if !ok {
			return fmt.Errorf("%q is not a host name or an IP address (a host alone: no scheme, port, path or wildcard)", h)
		}
	}
	return nil
}
