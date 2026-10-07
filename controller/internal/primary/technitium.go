package primary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Technitium is the "technitium" driver: it edits a Technitium DNS Server primary's
// zone-transfer and NOTIFY lists over its HTTP API (docs/design.md, Adoption, step 4): a
// node carrying a secondary zone must be allowed to transfer it and should be sent NOTIFY.
// Written from the API docs (/api/zones/options/get and /set), tried against a fake of
// them (internal/faketech): use DryRun first. The token never goes into an error, a log
// line or a report.
type Technitium struct {
	URL   string // e.g. https://primary.example:53443 (https only: the token is never sent over plain http)
	Token string // an API token (kept in the data volume, never in a config file)
	// HTTP reaches the API (Open gives Client's: the certificate verified, or pinned); nil:
	// Client's for URL, nothing pinned.
	HTTP   *http.Client
	DryRun bool // read the zone's options, say what would change, change nothing
	Logf   func(format string, args ...any)
	// Report, if set, hears what each Allow or Remove changes (or would, in a dry run).
	Report func(Edit)
}

// zoneOptions is the part of /api/zones/options/get this uses. Older servers list name
// servers (zoneTransferNameServers); newer ones a network ACL (zoneTransferNetworkACL).
type zoneOptions struct {
	ZoneTransfer            string    `json:"zoneTransfer"`
	ZoneTransferNameServers []string  `json:"zoneTransferNameServers"`
	ZoneTransferNetworkACL  *[]string `json:"zoneTransferNetworkACL"`
	Notify                  string    `json:"notify"`
	NotifyNameServers       []string  `json:"notifyNameServers"`
}

// ManualTechnitium is the change Allow makes, to make by hand in Technitium's console when
// the controller has no token to make it.
func ManualTechnitium(primary, zone, addr string) string {
	return fmt.Sprintf("on %s, zone %s, Zone Options: add %s to Zone Transfer (allowed name servers, or the network ACL) "+
		"and to Notify (specified name servers)", on(primary), zone, addr)
}

// CheckTechnitiumURL refuses a Technitium API address that isn't https://host[:port] (no
// user, path, query or fragment: the token goes in the request, never in the address).
func CheckTechnitiumURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("%q is not https://host:port (as https://primary.example:53443)", s)
	}
	return nil
}

func init() {
	Register(Driver{Kind: KindTechnitium, Name: "Technitium", API: true, Example: "https://<host>:53443",
		HTTPS:    "Technitium: Settings, Web Service, enable HTTPS (its self-signed certificate will do), port 53443 by default",
		CheckURL: CheckTechnitiumURL, Manual: ManualTechnitium,
		Open: func(url, token string, o Options) Primary {
			return &Technitium{URL: url, Token: token, HTTP: o.HTTP, DryRun: o.DryRun, Logf: o.Logf, Report: o.Report}
		}})
}

func (t *Technitium) Kind() string { return KindTechnitium }
func (t *Technitium) API() string  { return t.URL }

// Ready: reached over its API (Open makes one only with an address and a token).
func (t *Technitium) Ready() error { return nil }

// Manual is the change Allow makes, described to make by hand.
func (t *Technitium) Manual(primary, zone, addr string) string {
	return ManualTechnitium(primary, zone, addr)
}

func (t *Technitium) logf(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

// redact takes the token out of an error from the server or the HTTP client: as it is,
// and as a form or a URL encodes it (a server or proxy that echoes the request).
func (t *Technitium) redact(err error) error {
	if err == nil || t.Token == "" {
		return err
	}
	msg := err.Error()
	for _, f := range []string{t.Token, url.QueryEscape(t.Token), url.PathEscape(t.Token)} {
		msg = strings.ReplaceAll(msg, f, "[token]")
	}
	if msg == err.Error() {
		return err
	}
	return errors.New(msg)
}

func (t *Technitium) call(ctx context.Context, path string, form url.Values, v any) error {
	return t.redact(t.do(ctx, path, form, v))
}

func (t *Technitium) do(ctx context.Context, path string, form url.Values, v any) error {
	if t.Token == "" {
		return errors.New("technitium: no API token")
	}
	if !strings.HasPrefix(t.URL, "https://") { // Open never makes one; the token still never goes in clear
		return errors.New("technitium: the API address isn't https: nothing is sent to it over plain http")
	}
	form.Set("token", t.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(t.URL, "/")+path,
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := t.HTTP
	if hc == nil {
		hc = Client(Config{Kind: KindTechnitium, URL: t.URL})
	}
	// Never followed: a 307 or 308 would send the form, token and all, wherever it points.
	nc := *hc
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc = &nc
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		Status       string          `json:"status"`
		ErrorMessage string          `json:"errorMessage"`
		Response     json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("technitium %s: %s: not the API's reply (%v)", path, resp.Status, err)
	}
	if r.Status != "ok" {
		return fmt.Errorf("technitium %s: %s %s", path, r.Status, r.ErrorMessage)
	}
	if v != nil {
		return json.Unmarshal(r.Response, v)
	}
	return nil
}

func (t *Technitium) options(ctx context.Context, zone string) (zoneOptions, error) {
	var o zoneOptions
	err := t.call(ctx, "/api/zones/options/get", url.Values{"zone": {zone}}, &o)
	return o, err
}

// Lists reads the zone's transfer and NOTIFY lists (read-only).
func (t *Technitium) Lists(ctx context.Context, zone string) (Lists, error) {
	o, err := t.options(ctx, zone)
	if err != nil {
		return Lists{Zone: zone}, err
	}
	l := Lists{Zone: zone, Transfer: o.ZoneTransfer, TransferList: o.ZoneTransferNameServers, Notify: o.Notify,
		NotifyList: o.NotifyNameServers}
	if o.ZoneTransferNetworkACL != nil {
		l.TransferACL, l.TransferList = true, *o.ZoneTransferNetworkACL
	}
	switch l.Transfer {
	case "Allow":
		l.TransferAll = true
	case "AllowOnlySpecifiedNameServers", "AllowBothZoneAndSpecifiedNameServers", "UseSpecifiedNetworkACL",
		"AllowZoneNameServersAndUseSpecifiedNetworkACL":
		l.TransferUses = true
	}
	switch l.Notify {
	case "SpecifiedNameServers", "BothZoneAndSpecifiedNameServers":
		l.NotifyUses = true
	}
	if l.TransferList == nil {
		l.TransferList = []string{}
	}
	if l.NotifyList == nil {
		l.NotifyList = []string{}
	}
	return l, nil
}

// list is a list parameter: comma-separated, or "false" to clear it (the API's way).
func list(l []string) string {
	if len(l) == 0 {
		return "false"
	}
	return strings.Join(l, ",")
}

// Allow lets addr transfer zone and sends it the zone's NOTIFYs. A zone that allowed no
// one (or only its own name servers) now also allows the listed ones; a list it already
// has addr in is left as it is.
func (t *Technitium) Allow(ctx context.Context, zone, addr string) error {
	return t.edit(ctx, zone, addr, true)
}

// Remove takes addr off zone's transfer and NOTIFY lists (retiring a node); the modes
// are left as they are.
func (t *Technitium) Remove(ctx context.Context, zone, addr string) error {
	return t.edit(ctx, zone, addr, false)
}

func (t *Technitium) edit(ctx context.Context, zone, addr string, add bool) error {
	o, err := t.options(ctx, zone)
	if err != nil {
		return err
	}
	f := url.Values{"zone": {zone}}
	change := func(l []string) ([]string, bool) {
		has := slices.Contains(l, addr)
		switch {
		case add && !has:
			return append(slices.Clone(l), addr), true
		case !add && has:
			return slices.DeleteFunc(slices.Clone(l), func(s string) bool { return s == addr }), true
		}
		return l, false
	}
	var what []string
	if o.ZoneTransferNetworkACL != nil {
		if l, ok := change(*o.ZoneTransferNetworkACL); ok {
			f.Set("zoneTransferNetworkACL", list(l))
			what = append(what, "zone transfer ACL "+list(l))
		}
		if add {
			switch o.ZoneTransfer {
			case "Deny":
				f.Set("zoneTransfer", "UseSpecifiedNetworkACL")
			case "AllowOnlyZoneNameServers":
				f.Set("zoneTransfer", "AllowZoneNameServersAndUseSpecifiedNetworkACL")
			}
		}
	} else {
		if l, ok := change(o.ZoneTransferNameServers); ok {
			f.Set("zoneTransferNameServers", list(l))
			what = append(what, "zone transfer name servers "+list(l))
		}
		if add {
			switch o.ZoneTransfer {
			case "Deny":
				f.Set("zoneTransfer", "AllowOnlySpecifiedNameServers")
			case "AllowOnlyZoneNameServers":
				f.Set("zoneTransfer", "AllowBothZoneAndSpecifiedNameServers")
			}
		}
	}
	if l, ok := change(o.NotifyNameServers); ok {
		f.Set("notifyNameServers", list(l))
		what = append(what, "NOTIFY name servers "+list(l))
	}
	if add {
		switch o.Notify {
		case "None", "":
			f.Set("notify", "SpecifiedNameServers")
		case "ZoneNameServers":
			f.Set("notify", "BothZoneAndSpecifiedNameServers")
		}
	}
	for _, k := range []string{"zoneTransfer", "notify"} {
		if v := f.Get(k); v != "" {
			what = append(what, k+" "+v)
		}
	}
	ed := Edit{Zone: zone, Addr: addr, Add: add, Changes: what}
	switch {
	case len(what) == 0:
		t.logf("technitium: %s: %s already as wanted", zone, addr)
	case t.DryRun:
		t.logf("technitium: %s: would set %s", zone, strings.Join(what, "; "))
	default:
		if err := t.call(ctx, "/api/zones/options/set", f, nil); err != nil {
			return err
		}
		ed.Applied = true
		t.logf("technitium: %s: set %s", zone, strings.Join(what, "; "))
	}
	if t.Report != nil {
		t.Report(ed)
	}
	return nil
}
