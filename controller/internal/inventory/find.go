package inventory

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// Resolver sends one DNS query to a server (fleet.UDP is one).
type Resolver interface {
	Exchange(ctx context.Context, host string, m *dns.Msg) (*dns.Msg, error)
}

// What Find found.
const (
	FoundZone          = "zone"           // one of the fleet's zones already
	FoundWithin        = "within"         // a name inside one of the fleet's zones
	FoundPrimary       = "primary"        // a zone a configured primary serves
	FoundPrimaryWithin = "primary_within" // a name inside a zone a configured primary serves
	FoundNone          = "none"           // no configured primary serves it: host it here, or forward it
)

// Tried is one primary asked, and what it said.
type Tried struct {
	Primary string `json:"primary"`
	Answer  string `json:"answer"`
}

// Lookup is what Find found for a name.
type Lookup struct {
	Name  string `json:"name"`
	Found string `json:"found"`
	// Zone is the fleet's zone (FoundZone, FoundWithin).
	Zone *Zone `json:"zone,omitempty"`
	// Parent is the zone the name is inside (FoundWithin, FoundPrimaryWithin).
	Parent string `json:"parent,omitempty"`
	// Primary is the primary that serves the zone (FoundPrimary, FoundPrimaryWithin), and
	// Serial its SOA serial there.
	Primary string  `json:"primary,omitempty"`
	Serial  uint32  `json:"serial,omitempty"`
	Tried   []Tried `json:"tried"`
	Text    string  `json:"text"`
}

var labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)

// CheckName makes a typed zone name the inventory's (lowercase, no root dot) and refuses
// one that isn't a zone name: labels of 1 to 63 letters, digits, '_' and '-', not
// starting or ending with '-', 253 characters at most.
func CheckName(name string) (string, error) {
	n := canon(strings.TrimSpace(name))
	if n == "" {
		return "", fmt.Errorf("no zone name")
	}
	if len(n) > 253 {
		return "", fmt.Errorf("%q is not a zone name: over 253 characters", name)
	}
	for _, l := range strings.Split(n, ".") {
		if !labelRE.MatchString(l) {
			return "", fmt.Errorf("%q is not a zone name (labels of 1 to 63 letters, digits, '_' and '-', not starting or ending with '-')", name)
		}
	}
	return n, nil
}

// Find says where the zone name lives: one of the fleet's zones; else a zone one of the
// primaries serves, asked in order over DNS (an SOA query without recursion: a primary
// that holds the zone answers it authoritatively, whatever server it is); else a name
// inside one of the fleet's zones; else a name inside a zone a primary serves; else none.
// name is CheckName's.
func Find(ctx context.Context, r Resolver, inv Inventory, name string, primaries []string) Lookup {
	out := Lookup{Name: name, Tried: []Tried{}}
	if z, ok := inv.Of(name); ok {
		out.Found, out.Zone = FoundZone, &z
		out.Text = fmt.Sprintf("already one of the fleet's zones (%s)", z.Kind)
		return out
	}
	// A name inside one of the fleet's zones can still be a zone of its own, delegated to a
	// primary: the primaries are asked either way, and only a primary serving the name
	// itself outranks the fleet's zone that holds it.
	var within *Lookup
	for p := parent(name); p != ""; p = parent(p) {
		if z, ok := inv.Of(p); ok {
			within = &Lookup{Found: FoundWithin, Zone: &z, Parent: p,
				Text: fmt.Sprintf("a name inside %s, one of the fleet's zones (%s)", p, z.Kind)}
			break
		}
	}
	for _, p := range primaries {
		t, serial, zone := ask(ctx, r, p, name)
		out.Tried = append(out.Tried, t)
		switch {
		case zone == name:
			out.Found, out.Primary, out.Serial = FoundPrimary, p, serial
			out.Text = fmt.Sprintf("served by the primary at %s (serial %d)", p, serial)
			return out
		case zone != "" && within == nil:
			within = &Lookup{Found: FoundPrimaryWithin, Primary: p, Parent: zone, Serial: serial,
				Text: fmt.Sprintf("a name inside %s, which the primary at %s serves (serial %d)", zone, p, serial)}
		}
	}
	if within != nil {
		within.Name, within.Tried = name, out.Tried
		return *within
	}
	out.Found = FoundNone
	switch len(primaries) {
	case 0:
		out.Text = "no primary is configured to ask: host it here, or forward it"
	default:
		out.Text = "no configured primary serves it: host it here, or forward it"
	}
	return out
}

// ask asks the primary at p for name's SOA: the zone it is authoritative for that holds
// name ("" if none) and its serial.
func ask(ctx context.Context, r Resolver, p, name string) (Tried, uint32, string) {
	t := Tried{Primary: p}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeSOA)
	m.RecursionDesired = false
	resp, err := r.Exchange(ctx, p, m)
	switch {
	case err != nil:
		t.Answer = "no answer: " + err.Error()
		return t, 0, ""
	case resp == nil:
		t.Answer = "no answer"
		return t, 0, ""
	case resp.Rcode == dns.RcodeRefused:
		t.Answer = "refused: it doesn't serve this zone"
		return t, 0, ""
	case !resp.Authoritative:
		t.Answer = "not authoritative: it doesn't serve this zone"
		return t, 0, ""
	case resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError:
		t.Answer = "answered " + dns.RcodeToString[resp.Rcode]
		return t, 0, ""
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok && resp.Rcode == dns.RcodeSuccess && canon(soa.Hdr.Name) == name {
			t.Answer = fmt.Sprintf("serves it (serial %d)", soa.Serial)
			return t, soa.Serial, name
		}
	}
	for _, rr := range resp.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			z := canon(soa.Hdr.Name)
			if z != "" && strings.HasSuffix(name, "."+z) {
				t.Answer = fmt.Sprintf("serves %s, which holds it (serial %d)", z, soa.Serial)
				return t, soa.Serial, z
			}
		}
	}
	t.Answer = "authoritative, but no SOA for it"
	return t, 0, ""
}

// parent is the name one label up, "" above a top-level name.
func parent(name string) string {
	_, p, ok := strings.Cut(name, ".")
	if !ok {
		return ""
	}
	return p
}
