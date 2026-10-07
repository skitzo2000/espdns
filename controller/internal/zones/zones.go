// Package zones reads hosted zones and builds the bundle a REL_ZONES release carries
// (docs/design.md, Answering: hosted zones; format and the node's checks in
// firmware/main/hzone.h). Zones are RFC 1035 master files, one per zone, as BIND,
// Technitium and most DNS tools read and write them. The checks here are the node's, so a
// bundle this package builds is one the node takes (if it fits the node's memory limit).
//
// A bundle:
//
//	"EDZONES1", u16 zone count, then per zone: u8 apex length, apex (wire form), u32 record
//	count, then per record: u8 owner length, owner, u16 type, u32 TTL, u16 rdata length, rdata
//
// big-endian, class IN, names uncompressed.
package zones

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/skitzo2000/espdns/controller/internal/nodecfg"
)

const (
	Magic    = "EDZONES1"
	MaxZones = 32
	// What a node counts against its limit (firmware hz_mem): per zone, per record, plus
	// every owner and rdata byte.
	ZoneCost = 512
	RRCost   = 20
	// DefaultLimitKB is the limit on a node whose board definition doesn't set
	// memory.hosted_zones_kb (the chip image's default when a board leaves it out: firmware memplan.c).
	DefaultLimitKB = 64

	ttlMax = 1<<31 - 1
)

// The types a hosted zone may hold. Hosted zones are unsigned: no DNSSEC types.
var typeNames = map[uint16]string{
	dns.TypeA: "A", dns.TypeNS: "NS", dns.TypeCNAME: "CNAME", dns.TypeSOA: "SOA", dns.TypePTR: "PTR",
	dns.TypeMX: "MX", dns.TypeTXT: "TXT", dns.TypeAAAA: "AAAA", dns.TypeSRV: "SRV", dns.TypeCAA: "CAA",
}

// Record is one resource record in wire form: Owner lowercased and RData with its names
// uncompressed, as the node stores them.
type Record struct {
	Owner []byte
	Type  uint16
	TTL   uint32
	RData []byte
}

// Zone is one hosted zone: its apex (wire form, lowercased) and records.
type Zone struct {
	Apex    []byte
	Records []Record
}

// Name is the zone's name, without the trailing dot.
func (z *Zone) Name() string { return nameStr(z.Apex) }

// Serial is the zone's SOA serial (0 if it has no SOA).
func (z *Zone) Serial() uint32 {
	for _, r := range z.Records {
		if r.Type == dns.TypeSOA && bytes.Equal(r.Owner, z.Apex) && len(r.RData) >= 20 {
			return binary.BigEndian.Uint32(r.RData[len(r.RData)-20:])
		}
	}
	return 0
}

// Set is the hosted zones one bundle carries.
type Set struct {
	Zones []*Zone
}

// ParseMaster reads one zone from an RFC 1035 master file. origin is the zone's name; a
// relative name in the file is relative to it. $INCLUDE is not followed.
func ParseMaster(origin string, r io.Reader, filename string) (*Zone, error) {
	apex, err := wireName(dns.Fqdn(origin))
	if err != nil || len(apex) < 2 {
		return nil, fmt.Errorf("%s: %q is not a zone name", filename, origin)
	}
	z := &Zone{Apex: apex}
	zp := dns.NewZoneParser(r, dns.Fqdn(origin), filename)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		if h.Class != dns.ClassINET {
			return nil, fmt.Errorf("%s: %s: class %s; hosted zones are class IN", filename, h.Name, dns.ClassToString[h.Class])
		}
		if _, ok := typeNames[h.Rrtype]; !ok {
			return nil, fmt.Errorf("%s: %s: type %s not supported (A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA, SOA; no DNSSEC)",
				filename, h.Name, dns.TypeToString[h.Rrtype])
		}
		rec, err := toWire(rr)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", filename, h.Name, err)
		}
		z.Records = append(z.Records, rec)
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	z.normalize()
	return z, nil
}

// LoadFile reads a zone from a master file. spec is "origin=path", or a path named after
// its zone: "home.example.zone" holds home.example.
func LoadFile(spec string) (*Zone, error) {
	origin, path, ok := strings.Cut(spec, "=")
	if !ok {
		path = spec
		origin = strings.TrimSuffix(filepath.Base(path), ".zone")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMaster(origin, f, path)
}

// toWire packs rr without compression and splits out its parts.
func toWire(rr dns.RR) (Record, error) {
	buf := make([]byte, 65535+512)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return Record{}, err
	}
	b := buf[:n]
	ol, err := nameLen(b)
	if err != nil || ol+10 > len(b) {
		return Record{}, errors.New("cannot encode")
	}
	owner := bytes.ToLower(b[:ol])
	rd := b[ol+10:]
	if int(binary.BigEndian.Uint16(b[ol+8:])) != len(rd) {
		return Record{}, errors.New("cannot encode")
	}
	return Record{Owner: owner, Type: binary.BigEndian.Uint16(b[ol:]), TTL: binary.BigEndian.Uint32(b[ol+4:]),
		RData: append([]byte(nil), rd...)}, nil
}

// normalize sorts the records and drops exact duplicates (the node does the same), so a
// bundle's bytes depend only on what the zones hold.
func (z *Zone) normalize() {
	sort.SliceStable(z.Records, func(i, j int) bool {
		a, b := z.Records[i], z.Records[j]
		if c := bytes.Compare(a.Owner, b.Owner); c != 0 {
			return c < 0
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return bytes.Compare(a.RData, b.RData) < 0
	})
	out := z.Records[:0]
	for i, r := range z.Records {
		if i > 0 {
			p := out[len(out)-1]
			if bytes.Equal(p.Owner, r.Owner) && p.Type == r.Type && bytes.Equal(p.RData, r.RData) {
				continue
			}
		}
		out = append(out, r)
	}
	z.Records = out
}

// Mem is what the zones take in a node's memory (firmware hz_mem): the number its board's
// limit is checked against.
func (s *Set) Mem() int {
	m := 0
	for _, z := range s.Zones {
		m += ZoneCost + len(z.Records)*RRCost
		for _, r := range z.Records {
			m += len(r.Owner) + len(r.RData)
		}
	}
	return m
}

// Validate applies the node's checks (firmware hz_parse), except the memory limit.
func (s *Set) Validate() error {
	if len(s.Zones) > MaxZones {
		return fmt.Errorf("%d zones: at most %d", len(s.Zones), MaxZones)
	}
	seen := map[string]bool{}
	for _, z := range s.Zones {
		zn := z.Name()
		if _, err := nameLen(z.Apex); err != nil || len(z.Apex) < 2 || len(z.Apex) != mustLen(z.Apex) ||
			(z.Apex[0] == 1 && z.Apex[1] == '*') || innerStar(z.Apex) {
			return fmt.Errorf("zone %s: not a zone name", zn)
		}
		if seen[zn] {
			return fmt.Errorf("zone %s twice", zn)
		}
		seen[zn] = true
		if err := z.validate(); err != nil {
			return fmt.Errorf("zone %s: %w", zn, err)
		}
	}
	return nil
}

func mustLen(b []byte) int {
	n, _ := nameLen(b)
	return n
}

func (z *Zone) validate() error {
	soas := 0
	for _, r := range z.Records {
		on := nameStr(r.Owner)
		tn, ok := typeNames[r.Type]
		switch {
		case mustLen(r.Owner) != len(r.Owner) || len(r.Owner) == 0:
			return fmt.Errorf("%q: not a name", on)
		case !under(r.Owner, z.Apex):
			return fmt.Errorf("%s is outside the zone", on)
		case innerStar(r.Owner):
			return fmt.Errorf(`%s: "*" only as the first label`, on)
		case !ok:
			return fmt.Errorf("%s: type %d not supported (A, AAAA, CNAME, MX, TXT, SRV, NS, PTR, CAA, SOA; no DNSSEC)", on, r.Type)
		case r.TTL > ttlMax:
			return fmt.Errorf("%s %s: TTL above %d", on, tn, ttlMax)
		case !rdataOK(r.Type, r.RData):
			return fmt.Errorf("%s %s: malformed rdata", on, tn)
		case r.Type == dns.TypeSOA && !bytes.Equal(r.Owner, z.Apex):
			return fmt.Errorf("%s: SOA only at the apex", on)
		case r.Type == dns.TypeNS && len(r.Owner) > 1 && r.Owner[0] == 1 && r.Owner[1] == '*':
			// A wildcard can't be delegated (RFC 4592 4.2): firmware/main/hzone.c refuses it too.
			return fmt.Errorf("%s: NS at a wildcard name (a wildcard can't be delegated)", on)
		}
		if r.Type == dns.TypeSOA {
			soas++
		}
	}
	if soas != 1 {
		return errors.New("needs exactly one SOA, at the apex")
	}
	// Records grouped by owner: CNAMEs alone, and only NS and glue at and below a delegation.
	types := map[string][]uint16{}
	var owners []string
	for _, r := range z.Records {
		k := string(r.Owner)
		if _, ok := types[k]; !ok {
			owners = append(owners, k)
		}
		types[k] = append(types[k], r.Type)
	}
	hasNS := func(name []byte) bool {
		for _, t := range types[string(name)] {
			if t == dns.TypeNS {
				return true
			}
		}
		return false
	}
	for _, k := range owners {
		owner, ts := []byte(k), types[k]
		on := nameStr(owner)
		cnames := 0
		for _, t := range ts {
			if t == dns.TypeCNAME {
				cnames++
			}
		}
		if cnames > 1 {
			return fmt.Errorf("%s: more than one CNAME", on)
		}
		if cnames > 0 && len(ts) > 1 {
			return fmt.Errorf("%s: a CNAME and other records", on)
		}
		cut := -1
		for pos := 0; len(owner)-pos > len(z.Apex); pos += int(owner[pos]) + 1 {
			if hasNS(owner[pos:]) {
				cut = pos
				break
			}
		}
		if cut < 0 {
			continue
		}
		for _, t := range ts {
			if t != dns.TypeA && t != dns.TypeAAAA && !(cut == 0 && t == dns.TypeNS) {
				where := "at"
				if cut > 0 {
					where = "below"
				}
				return fmt.Errorf("%s: %s %s a delegation (only NS and A/AAAA glue)", on, typeNames[t], where)
			}
		}
	}
	return nil
}

// Clash is an error if a hosted zone is also a secondary or forward zone in a node config:
// a zone has exactly one source.
func (s *Set) Clash(c *nodecfg.Config) error {
	var names []string
	if c.Secondary != nil && c.Secondary.Zones != nil {
		names = append(names, *c.Secondary.Zones...)
	}
	if c.ForwardZones != nil {
		for _, f := range *c.ForwardZones {
			names = append(names, f.Zone)
		}
	}
	for _, z := range s.Zones {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSuffix(n, "."), z.Name()) {
				return fmt.Errorf("%s is both a hosted zone and a secondary or forward zone in the node config", z.Name())
			}
		}
	}
	return nil
}

// Bundle checks the zones and lays them out as the node receives them. limitKB is the
// node's memory limit for them (0: don't check).
func (s *Set) Bundle(limitKB int) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if m := s.Mem(); limitKB > 0 && m > limitKB*1024 {
		return nil, fmt.Errorf("the zones need %d KB; the node holds %d KB (memory.hosted_zones_kb in its board definition)",
			(m+1023)/1024, limitKB)
	}
	zs := append([]*Zone(nil), s.Zones...)
	sort.Slice(zs, func(i, j int) bool { return bytes.Compare(zs[i].Apex, zs[j].Apex) < 0 })
	b := []byte(Magic)
	b = binary.BigEndian.AppendUint16(b, uint16(len(zs)))
	for _, z := range zs {
		b = append(b, byte(len(z.Apex)))
		b = append(b, z.Apex...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(z.Records)))
		for _, r := range z.Records {
			b = append(b, byte(len(r.Owner)))
			b = append(b, r.Owner...)
			b = binary.BigEndian.AppendUint16(b, r.Type)
			b = binary.BigEndian.AppendUint32(b, r.TTL)
			b = binary.BigEndian.AppendUint16(b, uint16(len(r.RData)))
			b = append(b, r.RData...)
		}
	}
	return b, nil
}

// ParseBundle reads a bundle back (the structure; Validate checks the rest).
func ParseBundle(b []byte) (*Set, error) {
	if len(b) < 10 || string(b[:8]) != Magic {
		return nil, errors.New("not a zones bundle")
	}
	n := int(binary.BigEndian.Uint16(b[8:]))
	p := b[10:]
	short := errors.New("zones bundle cut short")
	name := func() ([]byte, error) {
		if len(p) < 1 || len(p) < 1+int(p[0]) {
			return nil, short
		}
		v := p[1 : 1+int(p[0])]
		p = p[1+int(p[0]):]
		return v, nil
	}
	s := &Set{}
	for i := 0; i < n; i++ {
		apex, err := name()
		if err != nil || len(p) < 4 {
			return nil, short
		}
		z := &Zone{Apex: apex}
		cnt := binary.BigEndian.Uint32(p)
		p = p[4:]
		for k := uint32(0); k < cnt; k++ {
			o, err := name()
			if err != nil || len(p) < 8 {
				return nil, short
			}
			rl := int(binary.BigEndian.Uint16(p[6:]))
			if len(p) < 8+rl {
				return nil, short
			}
			z.Records = append(z.Records, Record{Owner: o, Type: binary.BigEndian.Uint16(p), TTL: binary.BigEndian.Uint32(p[2:]),
				RData: p[8 : 8+rl]})
			p = p[8+rl:]
		}
		s.Zones = append(s.Zones, z)
	}
	if len(p) != 0 {
		return nil, fmt.Errorf("%d bytes after the last zone", len(p))
	}
	return s, nil
}

// ---- wire names ----

// nameLen is the length of the valid uncompressed wire name at the start of b.
func nameLen(b []byte) (int, error) {
	pos := 0
	for {
		if pos >= len(b) {
			return 0, errors.New("name cut short")
		}
		l := int(b[pos])
		if l > 63 {
			return 0, errors.New("bad label")
		}
		pos += l + 1
		if pos > 255 {
			return 0, errors.New("name too long")
		}
		if l == 0 {
			return pos, nil
		}
	}
}

func exactName(b []byte) bool {
	n, err := nameLen(b)
	return err == nil && n == len(b)
}

func wireName(s string) ([]byte, error) {
	buf := make([]byte, 256)
	n, err := dns.PackDomainName(s, buf, 0, nil, false)
	if err != nil {
		return nil, err
	}
	return bytes.ToLower(buf[:n]), nil
}

func nameStr(b []byte) string {
	var labels []string
	for pos := 0; pos < len(b) && b[pos] != 0; pos += int(b[pos]) + 1 {
		end := pos + 1 + int(b[pos])
		if end > len(b) {
			break
		}
		labels = append(labels, string(b[pos+1:end]))
	}
	if len(labels) == 0 {
		return "."
	}
	return strings.Join(labels, ".")
}

func innerStar(n []byte) bool {
	if len(n) == 0 {
		return false
	}
	for pos := int(n[0]) + 1; pos < len(n) && n[pos] != 0; pos += int(n[pos]) + 1 {
		if n[pos] == 1 && pos+1 < len(n) && n[pos+1] == '*' {
			return true
		}
	}
	return false
}

// under: name is apex or below it (both lowercased).
func under(name, apex []byte) bool {
	for pos := 0; len(name)-pos >= len(apex); pos += int(name[pos]) + 1 {
		if len(name)-pos == len(apex) {
			return bytes.Equal(name[pos:], apex)
		}
		if name[pos] == 0 {
			return false
		}
	}
	return false
}

func rdataOK(t uint16, rd []byte) bool {
	switch t {
	case dns.TypeA:
		return len(rd) == 4
	case dns.TypeAAAA:
		return len(rd) == 16
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
		return exactName(rd)
	case dns.TypeMX:
		return len(rd) > 2 && exactName(rd[2:])
	case dns.TypeSRV:
		return len(rd) > 6 && exactName(rd[6:])
	case dns.TypeTXT:
		if len(rd) == 0 {
			return false
		}
		pos := 0
		for pos < len(rd) {
			pos += int(rd[pos]) + 1
		}
		return pos == len(rd)
	case dns.TypeCAA:
		if len(rd) < 3 || rd[1] < 1 || rd[1] > 15 || int(rd[1])+2 > len(rd) {
			return false
		}
		for _, c := range rd[2 : 2+int(rd[1])] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				return false
			}
		}
		return true
	case dns.TypeSOA:
		a, err := nameLen(rd)
		if err != nil {
			return false
		}
		b, err := nameLen(rd[a:])
		return err == nil && a+b+20 == len(rd)
	}
	return false
}
