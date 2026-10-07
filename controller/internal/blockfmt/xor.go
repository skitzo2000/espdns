package blockfmt

import (
	"fmt"
	"math/bits"
)

// Xor is an xor filter (Graf & Lemire 2020) with f-bit fingerprints: about 1.23 × f bits
// per hash, and a wrong "yes" for about 1 in 2^f of the names not in the set. It is not a
// table on its own: it is the RAM pre-check in front of an exact table on SD, so only its
// "yes" answers read the card. (A binary fuse filter, the same idea, needs 1.13 × f.)
type Xor struct {
	f    int
	seed uint64
	bl   uint32 // slots per segment; three segments
	fp   []uint16
}

func mix(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func (t *Xor) slots(h uint64) (uint64, [3]uint32) {
	m := mix(h + t.seed)
	var s [3]uint32
	for i := range s {
		r := uint32(bits.RotateLeft64(m, 21*i))
		s[i] = uint32((uint64(r)*uint64(t.bl))>>32) + uint32(i)*t.bl
	}
	return (m ^ m>>32) & (1<<t.f - 1), s
}

func NewXor(hs []uint64, f int) (*Xor, error) {
	if f > 16 {
		return nil, fmt.Errorf("fingerprint over 16 bits")
	}
	n := len(hs)
	t := &Xor{f: f, bl: uint32((32+123*n/100)/3 + 1)}
	size := 3 * int(t.bl)
	for attempt := uint64(1); attempt <= 100; attempt++ {
		t.seed = mix(attempt * 0x9e3779b97f4a7c15)
		count := make([]uint8, size)
		xk := make([]uint64, size) // xor of the keys in each slot
		for _, h := range hs {
			_, s := t.slots(h)
			for _, i := range s {
				count[i]++
				xk[i] ^= h
			}
		}
		queue := make([]uint32, 0, size)
		for i, c := range count {
			if c == 1 {
				queue = append(queue, uint32(i))
			}
		}
		type peeled struct {
			key  uint64
			slot uint32
		}
		stack := make([]peeled, 0, n)
		for len(queue) > 0 {
			i := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if count[i] != 1 {
				continue
			}
			k := xk[i]
			stack = append(stack, peeled{k, i})
			_, s := t.slots(k)
			for _, j := range s {
				count[j]--
				xk[j] ^= k
				if count[j] == 1 {
					queue = append(queue, j)
				}
			}
		}
		if len(stack) != n {
			continue // a cycle; retry with another seed
		}
		t.fp = make([]uint16, size)
		for i := len(stack) - 1; i >= 0; i-- {
			fp, s := t.slots(stack[i].key)
			v := fp
			for _, j := range s {
				if j != stack[i].slot {
					v ^= uint64(t.fp[j])
				}
			}
			t.fp[stack[i].slot] = uint16(v)
		}
		return t, nil
	}
	return nil, fmt.Errorf("xor filter: no seed worked")
}

// Contains is false for a hash certainly not in the set.
func (t *Xor) Contains(h uint64) bool {
	fp, s := t.slots(h)
	return fp == uint64(t.fp[s[0]]^t.fp[s[1]]^t.fp[s[2]])
}

// Seed and SegmentLen are what the node needs to find a hash's three slots.
func (t *Xor) Seed() uint64       { return t.seed }
func (t *Xor) SegmentLen() uint32 { return t.bl }

// Packed is the fingerprints, f bits each, least significant bit first.
func (t *Xor) Packed() []byte {
	var b bitbuf
	for _, v := range t.fp {
		b.put(uint64(v), t.f)
	}
	out := make([]byte, (b.n+7)/8)
	for i := range out {
		out[i] = byte(b.w[i/8] >> (8 * (i % 8)))
	}
	return out
}
