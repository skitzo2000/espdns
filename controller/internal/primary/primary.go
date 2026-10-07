// Package primary is the zone primary the nodes copy their secondary zones from
// (docs/design.md, Adoption and addressing, step 4; Controller, integrations). The nodes are
// plain RFC secondaries: they transfer each zone over AXFR/IXFR and take the primary's
// NOTIFYs, so any standards-compliant primary works. What differs between primaries is how
// a node gets on the zone's transfer and NOTIFY lists, and that is all this package is:
//
//   - a Driver per kind of primary, registered here by kind: "manual" (the default, any
//     primary: the controller can't read or change the lists, so it names the change to
//     make by hand and goes on once you say it is made) and "technitium" (Technitium DNS
//     Server's HTTP API, with a token). A driver for another API (PowerDNS) or one that
//     only describes the change differently (BIND: allow-transfer and also-notify lines to
//     copy) is one more file registering a Driver: adoption, the controller's Zone primary
//     view and the CLI take any of them through Primary, unchanged.
//   - Open, which makes the Primary adoption and the view use from settings.json's
//     "primary" (Config), the address and the token: one that reaches the primary, or one
//     that is changed by hand and says why (no address, no token, a manual kind).
//
// An API is reached over https only, its certificate always verified: by the system's
// roots, or pinned by its fingerprint for a primary with a self-signed one (tls.go). A
// plain http address is refused wherever it is given (Check, Driver.CheckAPI), saying to
// switch the primary's API to https: the token is never sent over plain http. One already
// in settings.json (CheckSaved) lets the controller start, the primary paused: Open makes
// it a primary that is never reached (Ready: ErrPlainHTTP), until its https address is
// saved.
package primary

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	neturl "net/url"
	"slices"
	"sort"
	"strings"
)

// The kinds built in.
const (
	KindManual     = "manual"
	KindTechnitium = "technitium"
)

// Config is settings.json's "primary": the kind of primary, its API's address (https) for
// a kind driven over an API, and the SHA-256 fingerprint of the certificate pinned for it
// (a self-signed one; set by the confirm step, tls.go), if any.
type Config struct {
	Kind       string `json:"kind"`
	URL        string `json:"url,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
}

// SameTarget says whether c and o are the same primary: kind and address (a pin set or
// changed is the same primary).
func (c Config) SameTarget(o Config) bool { return c.Kind == o.Kind && c.URL == o.URL }

// IsZero: no zone primary set up (adoption then treats it as manual).
func (c Config) IsZero() bool { return c == Config{} }

// Check refuses an unknown kind, an API kind without its address or with one that isn't
// one (plain http among them), an address or a pin for a kind that has no API, and a pin
// that isn't a fingerprint. It is the check of an address given now (a settings save, a
// flag).
func (c Config) Check() error { return c.check(false) }

// CheckSaved is Check for a settings.json already written: a plain http address is let
// through, so the controller still starts and the address is fixed from its GUI; Open
// pauses that primary (ErrPlainHTTP), the token never sent to it.
func (c Config) CheckSaved() error { return c.check(true) }

// PlainHTTP says whether c is an API kind at a plain http address: paused (ErrPlainHTTP).
func (c Config) PlainHTTP() bool {
	d, ok := Lookup(c.Kind)
	return ok && d.API && plainHTTP(c.URL)
}

func plainHTTP(url string) bool {
	u, err := neturl.Parse(url)
	return err == nil && strings.EqualFold(u.Scheme, "http")
}

func (c Config) check(saved bool) error {
	d, ok := Lookup(c.Kind)
	switch {
	case c.Kind == "":
		return fmt.Errorf(`"kind": one of %s`, strings.Join(Kinds(), ", "))
	case !ok:
		return fmt.Errorf(`"kind": %q is not one of %s`, c.Kind, strings.Join(Kinds(), ", "))
	case !d.API && c.URL != "":
		return fmt.Errorf(`"url": the %s kind has no API to reach (leave "url" out)`, c.Kind)
	case d.API && c.URL == "":
		return fmt.Errorf(`"url": the %s kind needs its API's address (%s)`, c.Kind, d.Example)
	case !d.API && c.CertSHA256 != "":
		return fmt.Errorf(`"cert_sha256": the %s kind has no API to reach (leave it out)`, c.Kind)
	case d.API:
		if err := d.CheckAPI(c.URL); err != nil && !(saved && errors.Is(err, ErrPlainHTTP)) {
			return fmt.Errorf(`"url": %w`, err)
		}
		if c.CertSHA256 != "" {
			if err := checkPin(c.CertSHA256); err != nil {
				return fmt.Errorf(`"cert_sha256": %w`, err)
			}
		}
	}
	return nil
}

func (c Config) String() string {
	s := c.Kind
	if c.URL != "" {
		s += " " + c.URL
	}
	if c.CertSHA256 != "" {
		s += " (certificate pinned, SHA-256 " + c.CertSHA256 + ")"
	}
	return s
}

// Lists are a zone's transfer and NOTIFY settings on the primary, as its API gives them.
// The modes and lists are the server's own words, shown as they are; how they apply is
// said by the driver in TransferAll, TransferUses and NotifyUses, which Has reads, so
// nothing outside the driver knows one primary's modes.
type Lists struct {
	Zone string `json:"zone"`
	// Transfer is the zone transfer mode in the server's terms (Technitium's: Deny, Allow,
	// UseSpecifiedNetworkACL, ...); TransferList its addresses or name servers, or its
	// networks when TransferACL.
	Transfer     string   `json:"transfer"`
	TransferACL  bool     `json:"transfer_acl"`
	TransferList []string `json:"transfer_list"`
	// Notify is the NOTIFY mode in the server's terms; NotifyList its addresses.
	Notify     string   `json:"notify"`
	NotifyList []string `json:"notify_list"`
	// Set by the driver from the modes: anyone may transfer the zone (TransferAll); an
	// address in TransferList may (TransferUses); NOTIFYs go to NotifyList (NotifyUses).
	TransferAll  bool `json:"transfer_all"`
	TransferUses bool `json:"transfer_uses"`
	NotifyUses   bool `json:"notify_uses"`
}

// Has says whether addr may transfer the zone and is sent its NOTIFYs, by the lists as
// they are: the address in a list the modes use (or a network of the ACL that holds it),
// or a mode that allows anyone.
func (l Lists) Has(addr string) (transfer, notify bool) {
	a, _ := netip.ParseAddr(addr)
	in := func(list []string, acl bool) bool {
		for _, e := range list {
			if e == addr {
				return true
			}
			if p, err := netip.ParsePrefix(e); acl && err == nil && a.IsValid() && p.Contains(a) {
				return true
			}
		}
		return false
	}
	transfer = l.TransferAll || (l.TransferUses && in(l.TransferList, l.TransferACL))
	notify = l.NotifyUses && in(l.NotifyList, false)
	return transfer, notify
}

// Listed says whether addr is in either list, whatever the modes (an entry to remove).
func (l Lists) Listed(addr string) bool {
	return slices.Contains(l.TransferList, addr) || slices.Contains(l.NotifyList, addr)
}

// Edit is what an Allow or Remove changed in one zone, or would in a dry run.
type Edit struct {
	Zone    string   `json:"zone"`
	Addr    string   `json:"addr"`
	Add     bool     `json:"add"`
	Changes []string `json:"changes,omitempty"` // what is set; none: already as wanted
	Applied bool     `json:"applied"`           // set on the server (not a dry run, and something to change)
}

// ErrByHand: the primary isn't reached from here (a manual kind, or an API kind without
// its address or token): its lists can't be read or changed, only the change described
// (Manual). Errors wrap it with why.
var ErrByHand = errors.New("the zone primary is changed by hand")

// ErrPlainHTTP: the zone primary's API address in settings.json is plain http. It is
// never reached (the token would cross the network in clear): its calls are paused, and
// it is changed by hand, until its https address is saved and its certificate confirmed.
// The refusal of a plain http address given now (CheckAPI) wraps it too.
var ErrPlainHTTP = errors.New("the zone primary is plain http: switch its API to https and confirm its certificate")

// plainHTTPError is CheckAPI's refusal of a plain http address: ErrPlainHTTP, saying how.
type plainHTTPError struct{ msg string }

func (e *plainHTTPError) Error() string { return e.msg }
func (e *plainHTTPError) Unwrap() error { return ErrPlainHTTP }

// Primary is the zone primary as adoption, the controller's view and its jobs use it.
type Primary interface {
	// Kind is the driver's kind ("manual", "technitium").
	Kind() string
	// API is the address it is reached at; "" when it is changed by hand.
	API() string
	// Ready is nil when Lists, Allow and Remove reach the primary; otherwise why not
	// (wrapping ErrByHand), and they return that error.
	Ready() error
	// Lists reads a zone's transfer and NOTIFY lists (read-only).
	Lists(ctx context.Context, zone string) (Lists, error)
	// Allow lets addr transfer zone and sends it the zone's NOTIFYs.
	Allow(ctx context.Context, zone, addr string) error
	// Remove takes addr off zone's transfer and NOTIFY lists (retiring a node).
	Remove(ctx context.Context, zone, addr string) error
	// Manual is the exact change to make by hand on the primary (at the address primary,
	// as the node config names it) for addr to transfer zone and get its NOTIFYs: what
	// Allow does, for when it can't be done from here.
	Manual(primary, zone, addr string) string
}

// Options go to a driver opened over its API.
type Options struct {
	// HTTP is the client the driver reaches its API with: Open sets it (Client: https,
	// the certificate verified or pinned) unless a test gives its own.
	HTTP *http.Client
	// DryRun: read the zone's lists, say what would change, change nothing.
	DryRun bool
	Logf   func(format string, args ...any)
	// Report, if set, hears what each Allow or Remove changes (or would, in a dry run).
	Report func(Edit)
}

// Driver is one kind of primary.
type Driver struct {
	Kind string
	// Name is the primary's name in messages ("Technitium").
	Name string
	// API: driven over an HTTP API, with an address (Config.URL) and a token; false: never
	// reached, changed by hand (Manual).
	API bool
	// Example is an API address, for messages.
	Example string
	// HTTPS says how this kind of primary's API is switched to https, for the refusal of a
	// plain http address ("" says nothing more).
	HTTPS string
	// CheckURL checks an API address's form for this kind (API kinds); https only is
	// checked for every kind (CheckAPI).
	CheckURL func(string) error
	// Open makes the Primary for an API kind, with its address and token.
	Open func(url, token string, o Options) Primary
	// Manual describes the change by hand (Primary.Manual), for this kind whether or not
	// it can be driven from here.
	Manual func(primary, zone, addr string) string
}

var drivers = map[string]Driver{}

// Register adds a driver (from an init function).
func Register(d Driver) {
	if d.Kind == "" || d.Manual == nil || (d.API && (d.Open == nil || d.CheckURL == nil)) {
		panic("primary: incomplete driver " + d.Kind)
	}
	if _, ok := drivers[d.Kind]; ok {
		panic("primary: driver registered twice: " + d.Kind)
	}
	drivers[d.Kind] = d
}

// CheckAPI refuses an API address that isn't https (the token would cross the network in
// clear: never sent there), saying to switch the primary's API to https, and one the
// driver refuses.
func (d Driver) CheckAPI(url string) error {
	if plainHTTP(url) {
		how := ""
		if d.HTTPS != "" {
			how = " (" + d.HTTPS + ")"
		}
		return &plainHTTPError{fmt.Sprintf("%s is plain http: the API token would cross the network in clear, so it is never sent there. "+
			"Switch the primary's API to https%s and give its https address; a self-signed certificate is then pinned "+
			"(POST /api/primary/certificate, or espdns primary pin)", url, how)}
	}
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("%q is not an https address (as %s)", url, d.Example)
	}
	return d.CheckURL(url)
}

// Lookup is the driver of a kind.
func Lookup(kind string) (Driver, bool) {
	d, ok := drivers[kind]
	return d, ok
}

// APIKinds are the kinds registered that are driven over an API, sorted.
func APIKinds() []string {
	var out []string
	for _, k := range Kinds() {
		if drivers[k].API {
			out = append(out, k)
		}
	}
	return out
}

// Kinds are the kinds registered, sorted.
func Kinds() []string {
	var out []string
	for k := range drivers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Open makes the Primary for c: the driver over its API with the address, the token and
// the client that verifies the primary's certificate (pinned, with c.CertSHA256), or, when
// it can't be reached (a kind with no API, no address, a plain http address, no token),
// one changed by hand whose Ready says why: for plain http, ErrPlainHTTP (paused, the
// token never sent). An unknown kind, and an address otherwise refused, are errors.
func Open(c Config, token string, o Options) (Primary, error) {
	kind, url := c.Kind, c.URL
	d, ok := Lookup(kind)
	if !ok {
		return nil, fmt.Errorf("zone primary: kind %q is not one of %s", kind, strings.Join(Kinds(), ", "))
	}
	switch {
	case !d.API:
		return ByHand(d, fmt.Sprintf(`the zone primary is of kind %s: any primary, its lists changed by hand`, d.Kind)), nil
	case url == "":
		return ByHand(d, fmt.Sprintf(`no %s API address (settings.json "primary" "url", or -primary-url)`, d.Name)), nil
	case plainHTTP(url):
		return byHand{d: d, cause: ErrPlainHTTP}, nil
	case token == "":
		return ByHand(d, "no zone primary API token (espdns primary import, or the environment's)"), nil
	}
	if err := d.CheckAPI(url); err != nil {
		return nil, fmt.Errorf("zone primary: %w", err)
	}
	if c.CertSHA256 != "" {
		if err := checkPin(c.CertSHA256); err != nil {
			return nil, fmt.Errorf("zone primary: %w", err)
		}
	}
	if o.HTTP == nil {
		o.HTTP = Client(c)
	}
	return d.Open(url, token, o), nil
}

// ByHand is a primary of d's kind that isn't reached from here, for why.
func ByHand(d Driver, why string) Primary { return byHand{d: d, why: why} }

type byHand struct {
	d     Driver
	why   string
	cause error // ErrPlainHTTP: paused (why is its words)
}

func (b byHand) Kind() string { return b.d.Kind }
func (b byHand) API() string  { return "" }
func (b byHand) Ready() error {
	if b.cause != nil {
		return fmt.Errorf("%w: %w", ErrByHand, b.cause)
	}
	return fmt.Errorf("%w: %s", ErrByHand, b.why)
}
func (b byHand) Lists(context.Context, string) (Lists, error) {
	return Lists{}, b.Ready()
}
func (b byHand) Allow(context.Context, string, string) error  { return b.Ready() }
func (b byHand) Remove(context.Context, string, string) error { return b.Ready() }
func (b byHand) Manual(primary, zone, addr string) string     { return b.d.Manual(primary, zone, addr) }

// Why is why p is changed by hand ("" when it is reached), without ErrByHand's own words.
func Why(p Primary) string {
	err := p.Ready()
	if err == nil {
		return ""
	}
	return strings.TrimPrefix(err.Error(), ErrByHand.Error()+": ")
}

// on names the primary in a change by hand.
func on(primary string) string {
	s := "the zone primary"
	if primary != "" {
		s += " (" + primary + ")"
	}
	return s
}

// ManualGeneric is the change by hand on any RFC-compliant primary: the address allowed to
// transfer the zone and sent its NOTIFYs, in whatever terms the server uses.
func ManualGeneric(primary, zone, addr string) string {
	return fmt.Sprintf("on %s, zone %s: allow %s to transfer the zone (AXFR/IXFR) and send it the zone's NOTIFYs "+
		"(BIND: allow-transfer and also-notify; Knot: acl and notify; PowerDNS: ALSO-NOTIFY and allow-axfr-ips; "+
		"Technitium: Zone Options, Zone Transfer and Notify)", on(primary), zone, addr)
}

func init() {
	Register(Driver{Kind: KindManual, Name: "any zone primary", Manual: ManualGeneric})
}
