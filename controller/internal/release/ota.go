package release

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AppDesc is what an ESP-IDF app image says about itself (esp_app_desc_t), as
// firmware/tools/ota_push.py reads it.
type AppDesc struct {
	Project   string
	Version   string
	Built     string
	ElfSHA256 string // the first 8 bytes, hex: what /status reports as elf_sha256
}

// appDescOff is where esp_app_desc_t starts: esp_image_header_t (24) and the first
// segment's header (8).
const appDescOff = 32

// ParseAppDesc reads the app descriptor of a firmware image (an app .bin).
func ParseAppDesc(image []byte) (AppDesc, error) {
	if len(image) < appDescOff+256 || image[0] != 0xE9 {
		return AppDesc{}, errors.New("not an ESP app image")
	}
	d := image[appDescOff:]
	if binary.LittleEndian.Uint32(d) != 0xABCD5432 {
		return AppDesc{}, errors.New("image has no app descriptor")
	}
	str := func(off, n int) string {
		b, _, _ := bytes.Cut(d[off:off+n], []byte{0})
		return string(b)
	}
	return AppDesc{
		Version:   str(16, 32),
		Project:   str(48, 32),
		Built:     str(96, 16) + " " + str(80, 16),
		ElfSHA256: hex.EncodeToString(d[144:152]),
	}, nil
}

// builtinAddrMark is what precedes the address built into a firmware image (the firmware's
// CFG_BUILTIN_ADDR_MARK, main/cfg.h), NUL-terminated; "" for none.
const builtinAddrMark = "espdns:builtin-address="

// BuiltinAddress is the IPv4 address built into a firmware image (make STATIC_IP=..., a
// transitional image's), "" for none. known is false for an image from before the firmware
// marked it, which says nothing either way.
func BuiltinAddress(image []byte) (addr string, known bool) {
	i := bytes.Index(image, []byte(builtinAddrMark))
	if i < 0 {
		return "", false
	}
	rest := image[i+len(builtinAddrMark):]
	end := bytes.IndexByte(rest, 0)
	if end < 0 || end > len("255.255.255.255") {
		return "", false
	}
	return string(rest[:end]), true
}

// FirmwareOptions say how a firmware release is signed and applied.
type FirmwareOptions struct {
	// Image is the chip image the app was built as (esp32s3-octal, ...); the node must run it.
	Image string
	// Board is, for a node on firmware from before board definitions, the board the
	// transitional image was built for: those nodes check the board name instead.
	Board string
	// Later asks the node to stage the image and wait for a reboot command
	// (X-OTA-Reboot: later) instead of rebooting into it straight away. Firmware that
	// doesn't know the header reboots straight away.
	Later bool
}

// PushFirmware signs image as a firmware release for the node at host and posts it to
// /ota, as tools/ota_push.py does (without its HMAC path for pre-manifest firmware). It
// returns once the node took the image, before it runs it: internal/fleet waits for the
// node to confirm it, or roll it back.
func (p *Pusher) PushFirmware(ctx context.Context, host string, image []byte, o FirmwareOptions) (Pushed, error) {
	var out Pushed
	if _, err := ParseAppDesc(image); err != nil {
		return out, err
	}
	st, err := p.Status(ctx, host)
	if err != nil {
		return out, err
	}
	out.Before = st
	if err := p.trusted(host, st); err != nil {
		return out, err
	}
	// The name the node checks: its chip image; or, on firmware from before board
	// definitions, the board it was built for (only a transitional image for it fits).
	name := o.Image
	if st.Image != "" {
		if st.Image != o.Image {
			return out, fmt.Errorf("%s runs chip image %s, this is %s", host, st.Image, o.Image)
		}
	} else {
		if o.Board == "" || st.Board != o.Board {
			return out, fmt.Errorf("%s runs firmware from before board definitions, built for board %s: "+
				"push a transitional image for it (BOARD=%s)", host, st.Board, st.Board)
		}
		name = o.Board
	}
	node, seq, err := p.target(host, Firmware, st)
	if err != nil {
		return out, err
	}
	hdr, err := Header(p.Key, Firmware, p.KeyID, node, name, seq, image)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+host+"/ota",
		bytes.NewReader(append(hdr, image...)))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if o.Later {
		req.Header.Set("X-OTA-Reboot", "later")
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	reply := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s firmware seq %d rejected: %s %s", host, seq, resp.Status, reply)
	}
	out.Seq = seq
	out.Node = ParseReply(reply)
	out.Reply = fmt.Sprintf("firmware seq %d: %s", seq, out.Node.line())
	return out, nil
}
