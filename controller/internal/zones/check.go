package zones

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
	"github.com/skitzo2000/espdns/controller/internal/release"
)

// Checked is what espdns zones -check says of a set of zones: a line per zone, then the
// bundle against the limit. The controller's zone editor shows the same, from this code.
type Checked struct {
	Lines   []string `json:"lines"`
	Payload []byte   `json:"-"`
	Mem     int      `json:"mem"` // what the zones take in the node's memory (Mem)
	LimitKB int      `json:"limit_kb"`
}

// Check is espdns zones -check: the node's checks (Validate), a zone the node config also
// names as a secondary or forward zone (Clash, if cfg is given), then the bundle within
// limitKB (0: any size; below 0: no bundle, and no closing line). Lines holds what was said
// up to an error.
func Check(set *Set, cfg *nodecfg.Config, limitKB int) (Checked, error) {
	ck := Checked{LimitKB: limitKB}
	if err := set.Validate(); err != nil {
		return ck, err
	}
	if cfg != nil {
		if err := set.Clash(cfg); err != nil {
			return ck, err
		}
	}
	for _, z := range set.Zones {
		ck.Lines = append(ck.Lines, fmt.Sprintf("%s: serial %d, %d records", z.Name(), z.Serial(), len(z.Records)))
	}
	ck.Mem = set.Mem()
	if limitKB < 0 {
		return ck, nil
	}
	payload, err := set.Bundle(limitKB)
	if err != nil {
		return ck, err
	}
	ck.Payload = payload
	ck.Lines = append(ck.Lines, fmt.Sprintf("ok: %d zones, %d bytes, %d KB of a %d KB limit", len(set.Zones), len(payload),
		(ck.Mem+1023)/1024, limitKB))
	return ck, nil
}

// Payload is the bundle for the node at host, whose /status is st: refused by firmware from
// before hosted zones, and with a zone the node reports as one of its secondary zones or
// its forward zones (/status forward_zones: the node refuses a zone with two sources),
// checked against the limit the node reports. A rolling push's payload per
// node (fleet.Change.Payload), so the CLI and the Push page refuse it before any node is
// touched, and the zone editor's check per node.
func (s *Set) Payload(host string, st release.NodeStatus) ([]byte, error) {
	if st.Hosted == nil {
		return nil, fmt.Errorf("%s doesn't take hosted zones: update its firmware first", host)
	}
	var sec []string
	for _, z := range st.Zones {
		sec = append(sec, z.Name)
	}
	if err := s.ClashWith(sec, "a secondary zone of "+host+" (its /status)"); err != nil {
		return nil, err
	}
	if err := s.ClashWith(st.ForwardZones.Names(), "a forward zone of "+host+" (its /status)"); err != nil {
		return nil, err
	}
	return s.Bundle(st.Hosted.LimitBytes / 1024)
}

// Drops are the hosted zones the node, whose /status is st, serves now that the set
// doesn't have: a push of the set replaces the node's whole set, so it stops serving them.
func (s *Set) Drops(st release.NodeStatus) []string {
	if st.Hosted == nil {
		return nil
	}
	var out []string
	for _, hz := range st.Hosted.Zones {
		name := strings.ToLower(strings.TrimSuffix(hz.Name, "."))
		if !slices.ContainsFunc(s.Zones, func(z *Zone) bool { return strings.EqualFold(z.Name(), name) }) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// ClashWith is an error if a hosted zone is one of names, a node's secondary or forward
// zones (as its /status reports them): a node refuses a zone
// that is both. what says where the names are from.
func (s *Set) ClashWith(names []string, what string) error {
	for _, z := range s.Zones {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSuffix(n, "."), z.Name()) {
				return fmt.Errorf("%s is both a hosted zone and %s: the node refuses a zone with two sources", z.Name(), what)
			}
		}
	}
	return nil
}

// RecordText is one record as the zone holds it, in master file form.
type RecordText struct {
	Owner string `json:"owner"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

// Texts are the zone's records as the node gets them (lowercased owners, duplicates
// dropped, sorted), at most max of them (0: all).
func (z *Zone) Texts(max int) []RecordText {
	var out []RecordText
	for _, r := range z.Records {
		if max > 0 && len(out) == max {
			break
		}
		rt := RecordText{Owner: nameStr(r.Owner) + ".", Type: typeNames[r.Type], TTL: r.TTL}
		b := append([]byte(nil), r.Owner...)
		b = binary.BigEndian.AppendUint16(b, r.Type)
		b = binary.BigEndian.AppendUint16(b, dns.ClassINET)
		b = binary.BigEndian.AppendUint32(b, r.TTL)
		b = binary.BigEndian.AppendUint16(b, uint16(len(r.RData)))
		b = append(b, r.RData...)
		if rr, _, err := dns.UnpackRR(b, 0); err == nil {
			s := rr.String()
			hdr := rr.Header().String()
			rt.Data = strings.TrimPrefix(s, hdr)
		}
		out = append(out, rt)
	}
	return out
}

// ---- the SOA serial -----------------------------------------------------------------

// SerialAbove is a > b in serial number arithmetic (RFC 1982, as a secondary compares
// SOA serials): a is newer if it is ahead of b by less than 2^31, past 2^32-1 wrapping.
func SerialAbove(a, b uint32) bool { return a != b && a-b < 1<<31 }

// NextSerial is the serial after old that is above every one of above (SerialAbove): a
// date serial (YYYYMMDDnn) stays one, today's if it is behind; any other serial counts up
// by one.
func NextSerial(old uint32, above []uint32, now time.Time) uint32 {
	top := old
	for _, a := range above {
		if SerialAbove(a, top) {
			top = a
		}
	}
	next := top + 1
	if dateSerial(old) {
		today := uint32(now.Year()*1000000+int(now.Month())*10000+now.Day()*100) + 1
		if SerialAbove(today, next) {
			next = today
		}
	}
	if next == 0 { // past 2^32-1: wrapped (RFC 1982), which a secondary reads as newer; 0 avoided
		next = 1
	}
	return next
}

// dateSerial: a serial in the YYYYMMDDnn form.
func dateSerial(s uint32) bool {
	d := s / 100
	y, m, day := d/10000, d/100%100, d%100
	return y >= 1990 && y <= 2100 && m >= 1 && m <= 12 && day >= 1 && day <= 31
}

// SetSerial is text, a zone's master file, with its SOA serial set to serial and nothing
// else changed: the serial's token in the text replaced where it is, comments and layout
// kept. The result is read again and refused unless it holds the same records but the
// serial.
func SetSerial(origin string, text []byte, serial uint32) ([]byte, error) {
	before, err := ParseMaster(origin, bytes.NewReader(text), origin+".zone")
	if err != nil {
		return nil, err
	}
	cands := serialTokens(text)
	if len(cands) == 0 {
		return nil, errors.New("no SOA serial found in the text: edit it by hand")
	}
	for _, c := range cands {
		out := append(append(append([]byte(nil), text[:c[0]]...), strconv.FormatUint(uint64(serial), 10)...), text[c[1]:]...)
		after, err := ParseMaster(origin, bytes.NewReader(out), origin+".zone")
		if err == nil && after.Serial() == serial && sameButSerial(before, after) {
			return out, nil
		}
	}
	return nil, errors.New("the serial can't be set in this text: edit it by hand")
}

// sameButSerial: a and b hold the same records, the apex SOA's serial aside.
func sameButSerial(a, b *Zone) bool {
	if len(a.Records) != len(b.Records) {
		return false
	}
	for i, r := range a.Records {
		o := b.Records[i]
		if !bytes.Equal(r.Owner, o.Owner) || r.Type != o.Type || r.TTL != o.TTL || len(r.RData) != len(o.RData) {
			return false
		}
		if r.Type == dns.TypeSOA && len(r.RData) >= 20 {
			n := len(r.RData) - 20
			if !bytes.Equal(r.RData[:n], o.RData[:n]) || !bytes.Equal(r.RData[n+4:], o.RData[n+4:]) {
				return false
			}
		} else if !bytes.Equal(r.RData, o.RData) {
			return false
		}
	}
	return true
}

// serialTokens finds where the SOA serial may be in a master file: the third field after
// a token "SOA" (MNAME, RNAME, SERIAL), across parentheses and lines, comments and quoted
// strings skipped, where that field is a number. Each is a byte range; SetSerial takes the
// one that changes the SOA's serial and nothing else.
func serialTokens(text []byte) [][2]int {
	type tok struct {
		s          string
		start, end int
	}
	var toks []tok
	i := 0
	for i < len(text) {
		c := text[i]
		switch {
		case c == ';':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			toks = append(toks, tok{"\"", i, j})
			i = j + 1
		case c == '(' || c == ')':
			i++ // grouping only
		case unicode.IsSpace(rune(c)):
			i++
		default:
			j := i
			for j < len(text) && !unicode.IsSpace(rune(text[j])) && text[j] != ';' && text[j] != '(' && text[j] != ')' && text[j] != '"' {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			toks = append(toks, tok{string(text[i:min(j, len(text))]), i, min(j, len(text))})
			i = j
		}
	}
	var out [][2]int
	for k, t := range toks {
		if strings.EqualFold(t.s, "SOA") && k+3 < len(toks) {
			if s := toks[k+3]; s.s != "\"" {
				if _, err := strconv.ParseUint(s.s, 10, 32); err == nil {
					out = append(out, [2]int{s.start, s.end})
				}
			}
		}
	}
	return out
}
