package blocklist

import (
	"encoding/binary"
	"fmt"

	"github.com/skitzo2000/espdns/controller/internal/blockfmt"
)

// The blocklist file a node loads (firmware/main/blocklist.h reads it). Little-endian:
//
//	off  size  field
//	  0     8  magic "ESPDNSBL"
//	  8     1  version (2; version 1 had only the two block tables, a 96-byte header)
//	  9     1  hash bits (16..64)
//	 10     1  xor filter fingerprint bits (0 = no filter, else 1..16)
//	 11     5  reserved, zero
//	 16    16  SipHash-2-4 key
//	 32   128  four table descriptors, 32 bytes each: blocked exact, blocked suffix,
//	           allowed exact, allowed suffix (TExact..TAllowSuffix; any may be empty):
//	             +0 u32 hashes  +4 u32 sectors  +8 u32 index offset  +12 u32 sectors offset
//	             +16 u32 xor offset (0 = none)  +20 u32 xor segment length  +24 u64 xor seed
//	160        the sections: each table's index (u64 first hash of each sector) and xor
//	           fingerprints, then each table's 512-byte sectors, 512-aligned so the SD tier
//	           reads one sector per lookup
//
// A sector is: u8 count (hashes after the first), u8 l (low bits per hash), then count
// l-bit low parts and the unary high parts, least significant bit first: Elias-Fano over
// the offsets from the sector's first hash.
const (
	FileMagic   = "ESPDNSBL"
	FileVersion = 2
	FileHeader  = 32 + 32*NTables
)

// FileStats says where the bytes went.
type FileStats struct {
	Size, Index, Xor, Sectors int
}

// WriteFile lays out a file for a key, hash width and xor fingerprint width (0 = none).
// The tables are sorted hashes from Hashes with the same key and width. The overrides
// pushed to a node live are a file of this format too, usually with no filter.
func WriteFile(k Key, bits, xorBits int, ts Tables) ([]byte, FileStats, error) {
	if bits < 16 || bits > 64 || xorBits < 0 || xorBits > 16 {
		return nil, FileStats{}, fmt.Errorf("bad widths: %d-bit hashes, %d-bit xor", bits, xorBits)
	}
	var st FileStats
	out := make([]byte, FileHeader)
	copy(out, FileMagic)
	out[8], out[9], out[10] = FileVersion, byte(bits), byte(xorBits)
	binary.LittleEndian.PutUint64(out[16:], k.K0)
	binary.LittleEndian.PutUint64(out[24:], k.K1)

	var tables [NTables]*blockfmt.EFSector
	for i, hs := range ts {
		tables[i] = blockfmt.NewEFSector(hs)
	}
	for i, hs := range ts {
		d := 32 + 32*i // the descriptor; out grows, so always index it afresh
		t := tables[i]
		binary.LittleEndian.PutUint32(out[d:], uint32(len(hs)))
		binary.LittleEndian.PutUint32(out[d+4:], uint32(t.Count()))
		binary.LittleEndian.PutUint32(out[d+8:], uint32(len(out)))
		for s := range t.Count() {
			out = binary.LittleEndian.AppendUint64(out, t.First(s))
		}
		st.Index += 8 * t.Count()
		if xorBits > 0 && len(hs) > 0 {
			x, err := blockfmt.NewXor(hs, xorBits)
			if err != nil {
				return nil, st, err
			}
			binary.LittleEndian.PutUint32(out[d+16:], uint32(len(out)))
			binary.LittleEndian.PutUint32(out[d+20:], x.SegmentLen())
			binary.LittleEndian.PutUint64(out[d+24:], x.Seed())
			p := x.Packed()
			out = append(out, p...)
			st.Xor += len(p)
			for len(out)%8 != 0 {
				out = append(out, 0)
			}
		}
	}
	for i, t := range tables {
		for len(out)%blockfmt.Sector != 0 {
			out = append(out, 0)
		}
		binary.LittleEndian.PutUint32(out[32+32*i+12:], uint32(len(out)))
		for s := range t.Count() {
			out = append(out, t.SectorBytes(s)...)
		}
		st.Sectors += t.Count() * blockfmt.Sector
	}
	st.Size = len(out)
	return out, st, nil
}
