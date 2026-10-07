// Package blockfmt encodes a blocklist's hash tables as the node reads them
// (internal/blocklist lays out the file, firmware/main/blocklist.c reads it): a sorted set
// of w-bit hashes stored as Elias-Fano per 512-byte sector, with a RAM index of each
// sector's first hash, and an optional xor filter in front for the SD tier. The other
// formats measured against it are in docs/design.md (Blocking).
package blockfmt

import "math/bits"

// Sector is the unit a node reads from SD.
const Sector = 512

// bitbuf is a packed bit array, least significant bit first.
type bitbuf struct {
	w []uint64
	n int // bits used
}

func (b *bitbuf) put(v uint64, n int) {
	if n == 0 {
		return
	}
	for (b.n+n+63)/64 > len(b.w) {
		b.w = append(b.w, 0)
	}
	i, o := b.n/64, b.n%64
	b.w[i] |= v << o
	if o+n > 64 {
		b.w[i+1] |= v >> (64 - o)
	}
	b.n += n
}

func (b *bitbuf) get(pos, n int) uint64 {
	if n == 0 {
		return 0
	}
	i, o := pos/64, pos%64
	v := b.w[i] >> o
	if o+n > 64 && i+1 < len(b.w) {
		v |= b.w[i+1] << (64 - o)
	}
	if n == 64 {
		return v
	}
	return v & (1<<n - 1)
}

func (b *bitbuf) bit(pos int) bool { return b.w[pos/64]>>(pos%64)&1 != 0 }

// width is the number of bits needed to hold v.
func width(v uint64) int { return bits.Len64(v) }

// searchIndex returns the index of the last element ≤ h in a sorted index, or -1.
func searchIndex(idx []uint64, h uint64) int {
	lo, hi := 0, len(idx)
	for lo < hi {
		m := (lo + hi) / 2
		if idx[m] <= h {
			lo = m + 1
		} else {
			hi = m
		}
	}
	return lo - 1
}
