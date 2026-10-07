// blockbench measures the blocklist format (internal/blockfmt: 44-bit SipHash, Elias-Fano
// per 512-byte sector, an xor filter in front for the SD tier) on real lists: how many
// popular names a key blocks by accident, size per domain, lookup time on the host, and SD
// sectors read per query with and without the filter. With -write it writes a blocklist
// file and query names for the C benchmark (firmware/tests/bench_blocklist.c) instead.
//
//	blockbench -list wildcard:pro.txt -list hosts:hosts -popular top-1m.csv -bits 40,44
//	blockbench ... -bits 44 -write list.bin -queries q.txt
package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skitzo2000/espdns/controller/internal/blockfmt"
	"github.com/skitzo2000/espdns/controller/internal/blocklist"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	var lists listFlag
	flag.Var(&lists, "list", "kind:path of a blocklist (hosts, domains, wildcard, adblock); repeat")
	popular := flag.String("popular", "", "popular-domains list, Tranco CSV (rank,name)")
	bitsFlag := flag.String("bits", "40,44", "hash widths to try")
	keys := flag.Int("keys", 10, "keys to try for the popular-name check")
	write := flag.String("write", "", "instead of measuring, write a blocklist file (first -bits width) here")
	xorBits := flag.Int("xor", 10, "xor filter fingerprint bits, 0 for none")
	queries := flag.String("queries", "", "with -write: also write query names here, one per line")
	nq := flag.Int("nq", 100000, "with -write: query names to write (popular names, then blocked ones, alternating 9:1)")
	flag.Parse()

	var entries []blocklist.Entry
	for _, l := range lists {
		kind, path, ok := strings.Cut(l, ":")
		if !ok {
			log.Fatalf("-list %q: want kind:path", l)
		}
		k, err := blocklist.ParseKind(kind)
		if err != nil {
			log.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		st, err := blocklist.Parse(f, k, func(e blocklist.Entry) { entries = append(entries, e) })
		f.Close()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("- `%s` (%s): %d lines, %d entries, %d skipped\n", path[strings.LastIndexByte(path, '/')+1:], kind, st.Lines, st.Entries, st.Skipped)
	}
	c := blocklist.Compile(entries)
	n := len(c.Exact) + len(c.Suffix)
	fmt.Printf("- compiled: **%d domains** (%d exact, %d suffix; %d allowed); %d duplicates, %d covered by a parent, %d public suffixes dropped\n\n",
		n, len(c.Exact), len(c.Suffix), len(c.AllowExact)+len(c.AllowSuffix), c.Stats.Duplicates, c.Stats.Covered, c.Stats.PublicSuffix)

	verdict := c.Verdict()
	blocked := func(q string) bool { return verdict(q) == blocklist.Block }

	// Queries: popular names (mostly not blocked) and a sample of blocked names.
	var pop []string
	if *popular != "" {
		pop = readPopular(*popular)
	}
	var hits []string
	for i, s := range c.Exact {
		if i%4 == 0 {
			hits = append(hits, s)
		}
	}
	for i, s := range c.Suffix {
		if i%4 == 0 {
			hits = append(hits, "www."+s)
		}
	}
	popBlocked := 0
	for _, q := range pop {
		if blocked(q) {
			popBlocked++
		}
	}
	if len(pop) > 0 {
		fmt.Printf("- popular names: %d, of which the lists block %d on purpose\n\n", len(pop), popBlocked)
	}

	if *write != "" {
		w, _ := strconv.Atoi(strings.Split(*bitsFlag, ",")[0])
		k := newKey()
		file, st, err := blocklist.WriteFile(k, w, *xorBits, c.Hashes(k, uint(w)))
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*write, file, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %s: %d bytes (index %d, xor %d, sectors %d), %.2f bytes/domain\n", *write, st.Size, st.Index, st.Xor, st.Sectors, float64(st.Size)/float64(n))
		if *queries != "" {
			var b strings.Builder
			for i := 0; i < *nq && (i < len(pop) || i < len(hits)); i++ {
				if i%10 == 9 && len(hits) > 0 {
					b.WriteString(hits[(i*7919)%len(hits)])
				} else if len(pop) > 0 {
					b.WriteString(pop[i%len(pop)])
				} else {
					continue
				}
				b.WriteByte('\n')
			}
			if err := os.WriteFile(*queries, []byte(b.String()), 0o644); err != nil {
				log.Fatal(err)
			}
		}
		return
	}

	for _, ws := range strings.Split(*bitsFlag, ",") {
		w, err := strconv.Atoi(ws)
		if err != nil || w < 16 || w > 64 {
			log.Fatalf("bad -bits %q", ws)
		}
		run(c, uint(w), *xorBits, pop, hits, blocked, *keys)
	}
}

func readPopular(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		_, name, _ := strings.Cut(sc.Text(), ",")
		if c, ok := blocklist.Canon(name); ok {
			out = append(out, c)
		}
	}
	return out
}

func newKey() blocklist.Key {
	var b [16]byte
	rand.Read(b[:])
	return blocklist.KeyFromBytes(b)
}

// checks is one query's hashes: the full name for the exact table, then every suffix for
// the suffix table.
type checks struct {
	exact  uint64
	suffix []uint64
}

func hashQueries(k blocklist.Key, qs []string, w uint) []checks {
	out := make([]checks, len(qs))
	for i, q := range qs {
		out[i].exact = blocklist.Hash(k, q, w)
		for _, s := range blocklist.Suffixes(q) {
			out[i].suffix = append(out[i].suffix, blocklist.Hash(k, s, w))
		}
	}
	return out
}

// table is one membership test: the sector table, or the xor filter in front of it.
type table interface{ Contains(h uint64) bool }

// decide answers a query the way the node does; n is the checks it made.
func decide(ex, sx table, q checks) (blocked bool, n int) {
	n = 1
	if ex.Contains(q.exact) {
		return true, n
	}
	for _, h := range q.suffix {
		n++
		if sx.Contains(h) {
			return true, n
		}
	}
	return false, n
}

func run(c *blocklist.Compiled, w uint, xorBits int, pop, hits []string, blocked func(string) bool, keys int) {
	n := len(c.Exact) + len(c.Suffix)
	fmt.Printf("### %d-bit hashes, %d domains\n\n", w, n)

	// Accidental blocks of popular names, over several keys.
	if len(pop) > 0 {
		var counts []int
		first := -1
		for i := range keys {
			k := newKey()
			ex, sx := blocklist.Hashes(k, c.Exact, w), blocklist.Hashes(k, c.Suffix, w)
			wrong := 0
			for j, q := range hashQueries(k, pop, w) {
				in := func(set []uint64, h uint64) bool { _, ok := slices.BinarySearch(set, h); return ok }
				hit := in(ex, q.exact)
				for _, h := range q.suffix {
					hit = hit || in(sx, h)
				}
				if hit && !blocked(pop[j]) {
					wrong++
				}
			}
			counts = append(counts, wrong)
			if wrong == 0 && first < 0 {
				first = i + 1
			}
		}
		fmt.Printf("Popular names blocked by accident, per key (%d keys): %v", keys, counts)
		if first > 0 {
			fmt.Printf("; first clean key: try %d\n\n", first)
		} else {
			fmt.Printf("; no clean key in %d tries\n\n", keys)
		}
	}

	k := newKey()
	ts := c.Hashes(k, w)
	exH, sxH := ts[blocklist.TExact], ts[blocklist.TSuffix]
	_, st, err := blocklist.WriteFile(k, int(w), xorBits, ts)
	if err != nil {
		log.Fatal(err)
	}
	per := func(b int) float64 { return float64(b) / float64(n) }
	fmt.Printf("File: %.2f bytes/domain (%s): sectors %.2f, index %.3f, xor%d filter %.2f\n\n",
		per(st.Size), mb(float64(st.Size)), per(st.Sectors), per(st.Index), xorBits, per(st.Xor))

	qPop, qHit := hashQueries(k, pop, w), hashQueries(k, hits, w)
	all := append(append([]checks{}, qPop...), qHit...)
	ex, sx := blockfmt.NewEFSector(exH), blockfmt.NewEFSector(sxH)
	ref := make([]bool, len(all))
	nchecks := 0
	t0 := time.Now()
	for i, q := range all {
		var used int
		ref[i], used = decide(ex, sx, q)
		nchecks += used
	}
	el := time.Since(t0)
	fmt.Printf("Lookups on the host: %.0f ns/check, %.0f ns/query; %.2f checks per query (at most one sector read each in the SD tier without a filter)\n\n",
		float64(el.Nanoseconds())/float64(nchecks), float64(el.Nanoseconds())/float64(len(all)), float64(nchecks)/float64(len(all)))

	// The SD tier: the xor filter in RAM, the sector table on SD for its "yes" answers.
	if len(pop) > 0 && xorBits > 0 {
		xe, err1 := blockfmt.NewXor(exH, xorBits)
		xs, err2 := blockfmt.NewXor(sxH, xorBits)
		if err1 != nil || err2 != nil {
			log.Fatal(err1, err2)
		}
		sd, wrong := 0, 0
		for i, q := range qPop {
			if hit, _ := decide(xe, xs, q); hit {
				sd++
				if !ref[i] {
					wrong++
				}
			}
		}
		fmt.Printf("xor%d pre-check: %.2f%% of popular-name queries read SD, %.2f%% wrongly (filter only)\n\n",
			xorBits, 100*float64(sd)/float64(len(qPop)), 100*float64(wrong)/float64(len(qPop)))
	}
}

func mb(b float64) string { return fmt.Sprintf("%.2f MB", b/(1<<20)) }
