package blocklist

import (
	"bufio"
	"io"
	"strings"
)

// RPZStats counts what a Response Policy Zone held, by what became of each record. The
// QNAME triggers with a block or passthru action become entries; everything else is
// skipped and counted here (ParseStats.Skipped is their sum, but the zone's own records).
type RPZStats struct {
	Blocked  int `json:"blocked"`  // "name CNAME ." (NXDOMAIN) and "name CNAME *." (NODATA)
	Drop     int `json:"drop"`     // "name CNAME rpz-drop.": blocked too (the node answers, it doesn't drop)
	Allowed  int `json:"allowed"`  // "name CNAME rpz-passthru." (or "name CNAME name.", the older form): allowed
	Wildcard int `json:"wildcard"` // of the three above, "*.name": a suffix entry for name
	// Answers the zone gives in place of the real one (A, AAAA, TXT, a CNAME to a name):
	// a list or overrides file only blocks or allows, so these are skipped.
	LocalData int `json:"local_data"`
	TCPOnly   int `json:"tcp_only"` // "CNAME rpz-tcp-only.": no such action on a node
	// Triggers other than the query name, skipped: response IP (.rpz-ip), client IP
	// (.rpz-client-ip), name server name (.rpz-nsdname) and address (.rpz-nsip).
	IP       int `json:"ip"`
	ClientIP int `json:"client_ip"`
	NSDName  int `json:"nsdname"`
	NSIP     int `json:"nsip"`
	Zone     int `json:"zone"`       // the zone's own SOA and NS (at its apex), ignored
	Outside  int `json:"outside"`    // owner names outside the zone
	BadName  int `json:"bad_name"`   // trigger names a list can't hold (one label, bad characters, the apex)
	BadLine  int `json:"bad_line"`   // lines that aren't a record
	Includes int `json:"directives"` // $INCLUDE and $GENERATE, not followed
}

// rpzRecord is one record of the zone, its owner absolute (lowercase, trailing dot).
type rpzRecord struct {
	owner, typ, target string
}

// parseRPZ reads a Response Policy Zone (RFC 1035 master file syntax, as the RPZ feeds and
// BIND or Technitium publish them). The zone's apex is its SOA's owner, else the first
// $ORIGIN, else the root: then the owners are the trigger names as written. Under the apex,
// a QNAME trigger "name" or "*.name" with the action CNAME . (NXDOMAIN), CNAME *. (NODATA)
// or CNAME rpz-drop. is a block entry, with CNAME rpz-passthru. (or, the older form, a CNAME
// to the trigger's own name) an allow entry; "*.name" is
// a suffix entry for name (which also matches name itself: the compiler has no entry for
// the subdomains alone; feeds list both, and "name CNAME rpz-passthru." beside it leaves
// name allowed and its subdomains blocked).
func parseRPZ(r io.Reader, emit func(Entry)) (ParseStats, error) {
	st := ParseStats{RPZ: &RPZStats{}}
	z := &rpzLexer{sc: bufio.NewScanner(r), origin: "."}
	z.sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var recs []rpzRecord
	apex, firstOrigin, owner := "", "", ""
	for {
		toks, start, err := z.next(&st.Lines)
		if err != nil {
			return st, err
		}
		if toks == nil {
			break
		}
		if !start && strings.HasPrefix(toks[0], "$") {
			switch d := strings.ToUpper(toks[0]); d {
			case "$ORIGIN":
				if len(toks) < 2 {
					st.RPZ.BadLine++
					continue
				}
				z.origin = z.abs(toks[1])
				if firstOrigin == "" {
					firstOrigin = z.origin
				}
			case "$TTL":
			case "$INCLUDE", "$GENERATE":
				st.RPZ.Includes++
			default:
				st.RPZ.BadLine++
			}
			continue
		}
		if !start { // an owner given; else the last one's
			owner = z.abs(toks[0])
			toks = toks[1:]
		}
		// [TTL] [class] or [class] [TTL], then the type and its data
		for i := 0; i < 2 && len(toks) > 0 && (isTTL(toks[0]) || isClass(toks[0])); i++ {
			toks = toks[1:]
		}
		if owner == "" || len(toks) == 0 {
			st.RPZ.BadLine++
			continue
		}
		rec := rpzRecord{owner: owner, typ: strings.ToUpper(toks[0])}
		if len(toks) > 1 {
			rec.target = strings.ToLower(toks[1])
		}
		if rec.typ == "SOA" && apex == "" {
			apex = owner
		}
		recs = append(recs, rec)
	}
	if apex == "" {
		apex = firstOrigin
	}
	if apex == "" {
		apex = "."
	}
	for _, rec := range recs {
		skip := rpzEntry(rec, apex, st.RPZ, func(e Entry) { st.Entries++; emit(e) })
		if skip {
			st.Skipped++
		}
	}
	st.Skipped += st.RPZ.BadLine + st.RPZ.Includes
	return st, nil
}

// rpzEntry turns one record into an entry, counting it; true if it was skipped.
func rpzEntry(rec rpzRecord, apex string, rs *RPZStats, emit func(Entry)) bool {
	var trigger string
	switch {
	case rec.owner == apex:
		if rec.typ == "SOA" || rec.typ == "NS" {
			rs.Zone++
			return false
		}
		rs.BadName++
		return true
	case apex == ".":
		trigger = strings.TrimSuffix(rec.owner, ".")
	case strings.HasSuffix(rec.owner, "."+apex):
		trigger = strings.TrimSuffix(rec.owner, "."+apex)
	default:
		rs.Outside++
		return true
	}
	last := trigger[strings.LastIndexByte(trigger, '.')+1:]
	switch last {
	case "rpz-ip":
		rs.IP++
		return true
	case "rpz-client-ip":
		rs.ClientIP++
		return true
	case "rpz-nsdname":
		rs.NSDName++
		return true
	case "rpz-nsip":
		rs.NSIP++
		return true
	}
	// The action: a CNAME to "." or "*." blocks (NXDOMAIN, NODATA), to rpz-drop. too, to
	// rpz-passthru. allows; anything else is an answer of the zone's own.
	var count *int
	allow := false
	switch {
	case rec.typ != "CNAME":
		rs.LocalData++
		return true
	case rec.target == "." || rec.target == "*.":
		count = &rs.Blocked
	case rec.target == "rpz-drop.":
		count = &rs.Drop
	case rec.target == "rpz-passthru.", rec.target == trigger+".":
		// rpz-passthru., or the older form: a CNAME to the trigger's own name
		count, allow = &rs.Allowed, true
	case rec.target == "rpz-tcp-only.":
		rs.TCPOnly++
		return true
	default: // a CNAME to a name (a walled garden): local data
		rs.LocalData++
		return true
	}
	wild := strings.HasPrefix(trigger, "*.")
	name, ok := Canon(strings.TrimPrefix(trigger, "*."))
	if !ok || name == "localhost.localdomain" {
		rs.BadName++
		return true
	}
	*count++
	if wild {
		rs.Wildcard++
	}
	emit(Entry{Name: name, Suffix: wild, Allow: allow})
	return false
}

// isTTL: a TTL as master files write it, digits or units (1h30m, 1w).
func isTTL(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if (c < '0' || c > '9') && !strings.ContainsRune("smhdw", c) {
			return false
		}
	}
	return true
}

func isClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CH", "CS", "HS":
		return true
	}
	return false
}

// rpzLexer splits a master file into records: one per line, or across lines inside
// parentheses; ";" starts a comment outside quotes.
type rpzLexer struct {
	sc     *bufio.Scanner
	origin string
}

// abs makes a name absolute and lowercase: "@" is the origin, a name without a trailing
// dot is under it.
func (z *rpzLexer) abs(n string) string {
	n = strings.ToLower(n)
	switch {
	case n == "@":
		return z.origin
	case strings.HasSuffix(n, "."):
		return n
	case z.origin == ".":
		return n + "."
	}
	return n + "." + z.origin
}

// next returns the next record's tokens, and whether its line started with blank space
// (no owner: the last record's); nil at the end.
func (z *rpzLexer) next(lines *int) ([]string, bool, error) {
	var toks []string
	start, depth := false, 0
	for z.sc.Scan() {
		*lines++
		line := z.sc.Text()
		if len(toks) == 0 && depth == 0 {
			start = line != "" && (line[0] == ' ' || line[0] == '\t')
		}
		toks = tokens(line, toks, &depth)
		if depth == 0 && len(toks) > 0 {
			return toks, start, nil
		}
	}
	if err := z.sc.Err(); err != nil {
		return nil, false, err
	}
	if len(toks) > 0 { // an unclosed parenthesis at the end: what there is
		return toks, start, nil
	}
	return nil, false, nil
}

// tokens appends a line's fields to toks, dropping comments and parentheses (depth counts
// the open ones). A quoted string is one token.
func tokens(line string, toks []string, depth *int) []string {
	var b strings.Builder
	in, quoted := false, false
	flush := func() {
		if in {
			toks = append(toks, b.String())
			b.Reset()
			in = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted:
			b.WriteByte(c)
			if c == '\\' && i+1 < len(line) {
				i++
				b.WriteByte(line[i])
			} else if c == '"' {
				quoted = false
			}
		case c == '"':
			in, quoted = true, true
			b.WriteByte(c)
		case c == ';':
			flush()
			return toks
		case c == '(':
			flush()
			*depth++
		case c == ')':
			flush()
			if *depth > 0 {
				*depth--
			}
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		default:
			if c == '\\' && i+1 < len(line) {
				b.WriteByte(c)
				i++
				c = line[i]
			}
			in = true
			b.WriteByte(c)
		}
	}
	flush()
	return toks
}
