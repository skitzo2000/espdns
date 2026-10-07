package blockfmt

import "math/bits"

// EFSector is Elias-Fano inside each 512-byte sector: the offsets from the sector's first
// hash (in the RAM index) are split into high bits, unary-coded, and l low bits. Nearly
// Elias-Fano's size, but a lookup still reads one sector. A sector is a 2-byte header
// (count, l), the low bits, then the high bits.
type EFSector struct {
	data []bitbuf
	cnt  []uint8
	l    []uint8
	idx  []uint64
}

// sectorBits is the room in a sector after its 2-byte header.
const sectorBits = (Sector - 2) * 8

// efCost is the bits for m offsets whose largest is maxd: m low parts of l bits, plus a
// unary array of m ones and (maxd>>l)+1 zeros.
func efCost(m int, maxd uint64) (int, int) {
	l := max(0, width(maxd)-width(uint64(m)))
	return m*l + m + int(maxd>>l) + 1, l
}

// NewEFSector encodes sorted, distinct hashes.
func NewEFSector(hs []uint64) *EFSector {
	t := &EFSector{}
	for i := 0; i < len(hs); {
		base, j := hs[i], i+1
		for j < len(hs) && j-i < 256 {
			if c, _ := efCost(j-i, hs[j]-base); c > sectorBits {
				break
			}
			j++
		}
		m := j - i - 1
		var b bitbuf
		l := 0
		if m > 0 {
			_, l = efCost(m, hs[j-1]-base)
			for _, h := range hs[i+1 : j] {
				b.put((h-base)&(1<<l-1), l)
			}
			prev := uint64(0)
			for _, h := range hs[i+1 : j] {
				hi := (h - base) >> l
				for ; prev < hi; prev++ {
					b.put(0, 1)
				}
				b.put(1, 1)
			}
			b.put(0, 1)
		}
		t.idx = append(t.idx, base)
		t.data = append(t.data, b)
		t.cnt = append(t.cnt, uint8(m))
		t.l = append(t.l, uint8(l))
		i = j
	}
	return t
}

// Contains reports whether h is in the set, decoding the way the node does.
func (t *EFSector) Contains(h uint64) bool {
	s := searchIndex(t.idx, h)
	if s < 0 {
		return false
	}
	d := h - t.idx[s]
	if d == 0 {
		return true
	}
	if t.cnt[s] == 0 {
		return false
	}
	m, l, b := int(t.cnt[s]), int(t.l[s]), &t.data[s]
	hb, low := d>>l, d&(1<<l-1)
	// Skip hb zeros in the high part, counting the ones passed: that is the entry index.
	pos, idx, zeros := m*l, 0, uint64(0)
	for zeros < hb {
		avail := min(64, b.n-pos)
		if avail <= 0 {
			return false
		}
		word := b.get(pos, 64)
		if avail < 64 {
			word |= ^uint64(0) << avail // past the end: count as ones, never reached
		}
		z := bits.OnesCount64(^word)
		if zeros+uint64(z) < hb {
			zeros += uint64(z)
			idx += avail - z
			pos += avail
			continue
		}
		// The zero we want is in this word: walk to it.
		for zeros < hb {
			if word&1 == 0 {
				zeros++
			} else {
				idx++
			}
			word >>= 1
			pos++
		}
	}
	// Ones from here on are the entries in bucket hb, in order.
	for idx < m && pos < b.n && b.bit(pos) {
		v := b.get(idx*l, l)
		if v >= low {
			return v == low
		}
		idx, pos = idx+1, pos+1
	}
	return false
}

// Count is the number of sectors.
func (t *EFSector) Count() int { return len(t.idx) }

// First is the first hash of sector i, as the RAM index holds it.
func (t *EFSector) First(i int) uint64 { return t.idx[i] }

// SectorBytes is sector i as the node reads it: count, l, then the bits, least
// significant first.
func (t *EFSector) SectorBytes(i int) []byte {
	out := make([]byte, Sector)
	out[0], out[1] = t.cnt[i], t.l[i]
	for j, w := range t.data[i].w {
		for k := range 8 {
			if p := 2 + j*8 + k; p < Sector {
				out[p] = byte(w >> (8 * k))
			}
		}
	}
	return out
}
