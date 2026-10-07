// Package release builds and signs the releases the controller pushes to nodes: a 128-byte
// manifest and an ECDSA P-256 signature over it, then the payload (format in
// firmware/main/release.h; firmware/tools/release.py makes the same bytes for firmware).
package release

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const (
	ManifestLen = 128
	SigLen      = 64
	HeaderLen   = ManifestLen + SigLen
	magic       = "ESPDNS1\x00"
)

// Kind is what a release carries, and where the node puts it.
type Kind uint8

const (
	Firmware Kind = 1 + iota
	Config
	Zones
	Blocklist
	Overrides
	Control
)

var kindNames = [...]string{Firmware: "firmware", Config: "config", Zones: "zones", Blocklist: "blocklist",
	Overrides: "overrides", Control: "control"}

// String is the kind's name, as /status names it under "seq".
func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return fmt.Sprintf("kind%d", uint8(k))
}

func ParseKind(s string) (Kind, error) {
	for k, n := range kindNames {
		if n != "" && n == s {
			return Kind(k), nil
		}
	}
	return 0, fmt.Errorf("unknown release kind %q", s)
}

// Key slots: the release key the controller signs with, and the offline recovery key.
const (
	KeyRelease  = 0
	KeyRecovery = 1
)

// AnyNode as a target: the release applies on every node.
var AnyNode = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ParseMAC reads a node ID as /status gives it ("30:ed:a0:00:00:01").
func ParseMAC(s string) ([6]byte, error) {
	var m [6]byte
	b, err := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(s))
	if err != nil || len(b) != 6 {
		return m, fmt.Errorf("bad node ID %q", s)
	}
	copy(m[:], b)
	return m, nil
}

// Manifest lays out the 128 bytes that are signed. image is the chip image the node runs.
func Manifest(kind Kind, keyID uint8, target [6]byte, image string, seq uint64, payload []byte) ([]byte, error) {
	if len(image) > 15 {
		return nil, fmt.Errorf("image name %q longer than 15 bytes", image)
	}
	m := make([]byte, ManifestLen)
	copy(m, magic)
	m[8], m[9] = byte(kind), keyID
	copy(m[10:16], target[:])
	copy(m[16:32], image)
	binary.LittleEndian.PutUint64(m[32:], seq)
	binary.LittleEndian.PutUint64(m[40:], uint64(len(payload)))
	sum := sha256.Sum256(payload)
	copy(m[48:80], sum[:])
	return m, nil
}

// Sign signs a manifest (or a release's SHA256SUMS, internal/dist): ECDSA P-256 over its
// SHA-256, r || s, 32 bytes each, big-endian.
func Sign(key *ecdsa.PrivateKey, manifest []byte) ([]byte, error) {
	h := sha256.Sum256(manifest)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, SigLen)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// Header is the signed manifest that goes in front of the payload.
func Header(key *ecdsa.PrivateKey, kind Kind, keyID uint8, target [6]byte, image string, seq uint64, payload []byte) ([]byte, error) {
	m, err := Manifest(kind, keyID, target, image, seq, payload)
	if err != nil {
		return nil, err
	}
	sig, err := Sign(key, m)
	if err != nil {
		return nil, err
	}
	return append(m, sig...), nil
}

// Verify checks a header's signature with a public key (65 bytes, uncompressed).
func Verify(pub, header []byte) bool {
	if len(header) < HeaderLen {
		return false
	}
	return VerifySig(pub, header[:ManifestLen], header[ManifestLen:HeaderLen])
}

// VerifySig checks a signature Sign made over data (r || s) with a public key as the
// firmware has it built in (65 bytes, uncompressed: firmware/keys/release.pub).
func VerifySig(pub, data, sig []byte) bool {
	if len(sig) != SigLen {
		return false
	}
	k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		return false
	}
	h := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(k, h[:], r, s)
}

// SeqAhead is how far past the signer's clock a seq may go, and past a node's clock once it
// is set (firmware REL_SEQ_AHEAD_MS): seqs are times, and one far in the future would leave
// no seq above it for the releases after it (issue #55).
const SeqAhead = 24 * time.Hour

// NextSeq is the seq to sign after last (the last one this signer signed for the node and
// kind): milliseconds since 1970, or last + 1 if that isn't higher, so a controller rebuilt
// with an empty data directory still issues seqs the nodes accept. One more than SeqAhead
// past now is refused, whatever last says.
func NextSeq(last uint64, now time.Time) (uint64, error) {
	t := uint64(max(now.UnixMilli(), 0))
	limit := t + uint64(SeqAhead/time.Millisecond)
	if last >= limit {
		return 0, fmt.Errorf("the last seq %d is more than %v past this clock (%s): not signing above it "+
			"(a seq that far ahead would leave the node no seq for the releases after it)", last, SeqAhead,
			now.UTC().Format(time.RFC3339))
	}
	return max(t, last+1), nil
}

// LoadKey reads a PKCS#8 PEM private key (secrets/release.pem from `make keys`).
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(path, b)
}

// ParseKey parses a PKCS#8 PEM P-256 private key; name says where it came from in errors.
func ParseKey(name string, b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: not a PEM file", name)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New(name + ": not a P-256 key")
	}
	return ek, nil
}

// PublicRaw is the public key as nodes have it built in: 0x04 || X || Y.
func PublicRaw(k *ecdsa.PrivateKey) []byte {
	b, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err) // a P-256 key always encodes
	}
	return b
}

// Fingerprint is how /status names a trusted key: the first 8 bytes of its SHA-256, hex.
func Fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// Control commands (the payload of a Control release; firmware/main/block.h).
const (
	ctlPause    = 1
	ctlIdentify = 2
	ctlFlush    = 3
	ctlReboot   = 4
	ctlRevert   = 5
)

// IdentifyMax is the longest identify a node runs; a longer one is cut to this.
const IdentifyMax = time.Hour

// PauseMax is the longest pause the CLI and the controller send (a pause forgotten leaves
// the node unblocked; a reboot ends one anyway); a longer one is refused.
const PauseMax = 7 * 24 * time.Hour

// ctlSeconds is a command with a u32 of seconds from when the node receives it, rounded up
// (so a short one isn't a stop); 0 or less stops it.
func ctlSeconds(cmd byte, d time.Duration) []byte {
	p := []byte{cmd, 0, 0, 0, 0}
	secs := (max(d, 0) + time.Second - 1) / time.Second
	binary.LittleEndian.PutUint32(p[1:], uint32(min(secs, 1<<32-1)))
	return p
}

// PausePayload pauses blocking for d from when the node receives it, in whole seconds
// rounded up (so a short pause isn't a resume); 0 or less resumes.
func PausePayload(d time.Duration) []byte { return ctlSeconds(ctlPause, d) }

// IdentifyPayload makes the node's LED flicker for d (rounded up to whole seconds, at most
// IdentifyMax), so it can be told from the others; 0 or less stops it.
func IdentifyPayload(d time.Duration) []byte { return ctlSeconds(ctlIdentify, min(d, IdentifyMax)) }

// FlushPayload drops every answer in the node's cache.
func FlushPayload() []byte { return []byte{ctlFlush} }

// RevertPayload sends the node's blocklist, overrides or hosted zones (k) back to the older
// copy it keeps in its other slot, live (a list at its next reboot, when two copies don't
// fit: reboot pending). The node keeps to it across reboots until a newer one is pushed, and
// refuses it when it holds no older copy.
func RevertPayload(k Kind) ([]byte, error) {
	if k != Blocklist && k != Overrides && k != Zones {
		return nil, fmt.Errorf("revert takes blocklist, overrides or zones, not %s", k)
	}
	return []byte{ctlRevert, byte(k)}, nil
}

// RebootPayload reboots the node delay after it receives it (in whole milliseconds). With
// onlyIfPending the node reboots only if a release it took is waiting for one (/status
// "reboot": {"pending": true}), so a repeated command can't take it down twice.
func RebootPayload(delay time.Duration, onlyIfPending bool) []byte {
	p := []byte{ctlReboot, 0, 0, 0, 0, 0}
	ms := min(max(delay, 0)/time.Millisecond, 1<<32-1)
	binary.LittleEndian.PutUint32(p[1:], uint32(ms))
	if onlyIfPending {
		p[5] = 1
	}
	return p
}
