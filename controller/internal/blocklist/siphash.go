package blocklist

import (
	"encoding/binary"
	"math/bits"
)

// Key is a SipHash-2-4 key: k0 and k1 are bytes 0..7 and 8..15, little-endian.
type Key struct{ K0, K1 uint64 }

// KeyFromBytes reads a 16-byte key the way the reference implementation does.
func KeyFromBytes(b [16]byte) Key {
	return Key{binary.LittleEndian.Uint64(b[:8]), binary.LittleEndian.Uint64(b[8:])}
}

// SipHash is SipHash-2-4 (Aumasson & Bernstein). The node runs the same function in C.
func SipHash(k Key, p []byte) uint64 {
	v0 := k.K0 ^ 0x736f6d6570736575
	v1 := k.K1 ^ 0x646f72616e646f6d
	v2 := k.K0 ^ 0x6c7967656e657261
	v3 := k.K1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}
	n := len(p)
	for len(p) >= 8 {
		m := binary.LittleEndian.Uint64(p)
		v3 ^= m
		round()
		round()
		v0 ^= m
		p = p[8:]
	}
	b := uint64(n) << 56
	for i := len(p) - 1; i >= 0; i-- {
		b |= uint64(p[i]) << (8 * uint(i))
	}
	v3 ^= b
	round()
	round()
	v0 ^= b
	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}
