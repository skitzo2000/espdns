/*
 * Signed release manifests (portable: needs only mbedTLS).
 *
 * Every push to a node starts with a 128-byte manifest and a 64-byte ECDSA P-256
 * signature over it, followed by the payload:
 *
 *   off  size  field
 *     0     8  magic "ESPDNS1\0"
 *     8     1  kind (rel_kind_t)
 *     9     1  key_id: 0 = release key, 1 = offline recovery key
 *    10     6  target node ID (base MAC), ff:ff:ff:ff:ff:ff = any node
 *    16    16  chip image name, NUL-padded (must match the running firmware; firmware from
 *                before board definitions checked a board name here)
 *    32     8  seq, little-endian; must be above the last one accepted for this kind, and
 *                no further ahead than rel_seq_limit allows
 *    40     8  payload length, little-endian
 *    48    32  SHA-256 of the payload
 *    80    48  reserved, must be zero
 *   128    64  signature r || s (big-endian) over SHA-256(bytes 0..127)
 *
 * The node checks all of this before it reads the payload, then checks the payload's
 * SHA-256 as it streams in. Binding to node, board and seq stops a release being pushed
 * to the wrong node or replayed later; the controller rolls back by re-signing an old
 * payload with a new seq, and signs for the node ID it pinned at adoption with seqs from
 * its own record, never from /status (controller internal/pins).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define REL_MANIFEST_LEN 128
#define REL_SIG_LEN      64
#define REL_HEADER_LEN   (REL_MANIFEST_LEN + REL_SIG_LEN)
#define REL_PUBKEY_LEN   65 /* uncompressed P-256 point: 0x04 || X || Y */
#define REL_NKEYS        2

typedef enum {
    REL_FIRMWARE = 1,
    REL_CONFIG,
    REL_ZONES,
    REL_BLOCKLIST,
    REL_OVERRIDES,
    REL_CONTROL,
    REL_KIND_END
} rel_kind_t;

typedef struct {
    uint8_t kind;
    uint8_t key_id;
    uint8_t target[6];
    char board[17];
    uint64_t seq;
    uint64_t payload_len;
    uint8_t sha256[32];
} rel_manifest_t;

/* What this node trusts and who it is. keys[i] may be NULL (no key in that slot). */
typedef struct {
    const uint8_t *keys[REL_NKEYS];
    uint8_t node_id[6];
    const char *board;     /* the chip image this firmware is, e.g. esp32s3-octal */
    const char *board_alt; /* also accepted, or NULL: a transitional image's old board name */
} rel_trust_t;

/* Checks the header: format, signature, target, board, and last_seq < seq <= max_seq.
 * Returns NULL and fills *m if the release may be applied, else a short reason: for a seq
 * above max_seq, rel_why_ahead. A copy already taken (a stored slot checked again) passes
 * UINT64_MAX. */
const char *rel_verify(const uint8_t hdr[REL_HEADER_LEN], const rel_trust_t *t, uint64_t last_seq,
                       uint64_t max_seq, rel_manifest_t *m);
extern const char rel_why_ahead[];

/*
 * The highest seq a node takes (issue #55). Seqs are milliseconds since 1970 (the signer's
 * clock, or one above the last it signed): a seq accepted is kept for good, and one far in
 * the future, say a signer misled into signing near 2^64, would leave no seq above it, and
 * every later release of that kind refused until a USB reflash erases NVS. So once SNTP has
 * set its clock, a node takes a seq no further ahead than that clock plus REL_SEQ_AHEAD_MS
 * (room for the signer's clock running ahead).
 *
 * Before its clock is set, a node has nothing to measure a seq against and puts no limit
 * on it: any seq above the one it holds is taken. A limit made up without a clock (its
 * newest seq or build time plus some margin) could refuse every release to a node that
 * never syncs, which only a USB reflash would fix. The signers carry the bound there: they
 * sign no further than REL_SEQ_AHEAD_MS past their own clock, from their own record of the
 * last seq (controller release.SeqAhead and internal/pins, tools/release.py SEQ_AHEAD_MS).
 */
#define REL_SEQ_AHEAD_MS (24ULL * 3600 * 1000)

/* synced: the clock was set over SNTP, now_ms being it. UINT64_MAX (no limit) when not;
 * saturates. */
uint64_t rel_seq_limit(bool synced, uint64_t now_ms);

const char *rel_kind_name(uint8_t kind);
