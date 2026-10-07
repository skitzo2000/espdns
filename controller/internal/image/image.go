// Package image assembles a board's whole-flash image from a chip image (exported by
// `make export-images` in firmware/, or a release's) and the board's definition, the way tools/factory.py
// does with esptool, so the controller can flash any board without a toolchain.
package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Chip is one exported chip image: data/firmware/images/<image>/image.json and its files.
type Chip struct {
	Image      string         `json:"image"`
	Chip       string         `json:"chip"`
	ChipFamily string         `json:"chip_family"` // ESP Web Tools' name, e.g. ESP32-S3
	Offsets    map[string]int `json:"offsets"`
	FlashMode  string         `json:"flash_mode"`
	FlashFreq  string         `json:"flash_freq"`
	Version    string         `json:"version"`
	Built      string         `json:"built"`
	ElfSHA256  string         `json:"elf_sha256"`
	dir        string
}

// List returns the chip images under dir.
func List(dir string) ([]Chip, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*", "image.json"))
	if err != nil {
		return nil, err
	}
	out := []Chip{}
	for _, f := range files {
		c, err := Open(filepath.Dir(f))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out, nil
}

// Open reads one chip image directory.
func Open(dir string) (Chip, error) {
	var c Chip
	b, err := os.ReadFile(filepath.Join(dir, "image.json"))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", dir, err)
	}
	c.dir = dir
	return c, nil
}

// Manifest is the ESP Web Tools manifest that installs one whole-flash image (Assemble's)
// at offset 0, erasing the flash first; path is the image's URL, relative to the manifest's.
// The controller's builder serves it for the image it assembled, and a release carries one
// beside each board's factory image (internal/dist).
func (c Chip) Manifest(board, path string) map[string]any {
	return map[string]any{
		"name":                     "espDNS " + board,
		"version":                  c.Version,
		"new_install_prompt_erase": true,
		// ESP Web Tools only installs: the dashboard sets up Wi-Fi itself over Improv, with
		// its own port handling
		"new_install_improv_wait_time": 0,
		"builds": []any{map[string]any{
			"chipFamily": c.ChipFamily,
			"parts":      []any{map[string]any{"path": path, "offset": 0}},
		}},
	}
}

// Dir is the directory the chip image was read from.
func (c Chip) Dir() string { return c.dir }

// flashSizeCode is the bootloader header's flash size field (esptool's FLASH_SIZES).
var flashSizeCode = map[int]byte{1: 0, 2: 1, 4: 2, 8: 3, 16: 4, 32: 5, 64: 6, 128: 7}

// Assemble returns the whole-flash image, written at offset 0: bootloader (with the board's
// flash size), the partition table for that size, OTA data, the board partition and the app.
// Gaps are 0xFF, as esptool merge_bin leaves them; NVS is erased.
func (c Chip) Assemble(flashMB int, boardPart []byte) ([]byte, error) {
	code, ok := flashSizeCode[flashMB]
	if !ok {
		return nil, fmt.Errorf("flash size %d MB: not one esptool knows", flashMB)
	}
	table := "partitions-8mb.bin"
	if flashMB < 8 {
		table = "partitions-4mb.bin"
	}
	type part struct {
		off  int
		data []byte
	}
	var parts []part
	for _, name := range []string{"bootloader.bin", table, "ota_data_initial.bin", "app.bin"} {
		off, ok := c.Offsets[name]
		if !ok {
			return nil, fmt.Errorf("%s: no offset for %s", c.Image, name)
		}
		data, err := os.ReadFile(filepath.Join(c.dir, name))
		if err != nil {
			return nil, err
		}
		if name == "bootloader.bin" {
			if data, err = setFlashSize(data, code); err != nil {
				return nil, fmt.Errorf("%s bootloader: %w", c.Image, err)
			}
		}
		parts = append(parts, part{off, data})
	}
	parts = append(parts, part{c.Offsets["board"], boardPart})
	sort.Slice(parts, func(i, j int) bool { return parts[i].off < parts[j].off })

	end := 0
	for i, p := range parts {
		if i > 0 && p.off < parts[i-1].off+len(parts[i-1].data) {
			return nil, fmt.Errorf("%s: parts overlap at 0x%x", c.Image, p.off)
		}
		end = p.off + len(p.data)
	}
	if end > flashMB<<20 {
		return nil, fmt.Errorf("image is %d bytes, more than %d MB of flash", end, flashMB)
	}
	out := bytes.Repeat([]byte{0xFF}, end)
	for _, p := range parts {
		copy(out[p.off:], p.data)
	}
	return out, nil
}

// setFlashSize sets the flash size in an ESP image header (byte 3, high nibble) and, when the
// image carries a SHA-256 digest of itself, recomputes it, as esptool does when it flashes.
//
// Layout: 24-byte header (magic 0xE9, segment count at 1, hash_appended at 23), segments of
// (load address u32, length u32, data), a checksum byte that ends a 16-byte-aligned block,
// then the 32-byte SHA-256 of everything before it.
func setFlashSize(img []byte, code byte) ([]byte, error) {
	if len(img) < 24 || img[0] != 0xE9 {
		return nil, errors.New("not an ESP image")
	}
	out := append([]byte(nil), img...)
	out[3] = code<<4 | out[3]&0x0F
	if out[23] != 1 {
		return out, nil
	}
	pos := 24
	for i := 0; i < int(out[1]); i++ {
		if pos+8 > len(out) {
			return nil, errors.New("truncated segment header")
		}
		pos += 8 + int(binary.LittleEndian.Uint32(out[pos+4:]))
	}
	pos = (pos/16)*16 + 16 // the checksum byte ends the next 16-byte block
	if pos+32 > len(out) {
		return nil, errors.New("no room for the appended SHA-256")
	}
	digest := sha256.Sum256(out[:pos])
	copy(out[pos:], digest[:])
	return out, nil
}
