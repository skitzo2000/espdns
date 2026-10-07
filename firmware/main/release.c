#include "release.h"

#include <string.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

static const uint8_t MAGIC[8] = "ESPDNS1";
static const uint8_t ANY_NODE[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static uint64_t rd64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

static bool sig_ok(const uint8_t *pub, const uint8_t *msg, size_t len, const uint8_t *sig)
{
    uint8_t hash[32];
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_sha256(msg, len, hash, 0) == 0 &&
              mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &q, pub, REL_PUBKEY_LEN) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &q) == 0 &&
              mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
              mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0 &&
              mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &q, &r, &s) == 0;
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

const char rel_why_ahead[] = "seq too far ahead of this node's clock";

const char *rel_verify(const uint8_t hdr[REL_HEADER_LEN], const rel_trust_t *t, uint64_t last_seq,
                       uint64_t max_seq, rel_manifest_t *m)
{
    memset(m, 0, sizeof(*m));
    if (memcmp(hdr, MAGIC, sizeof(MAGIC)) != 0)
        return "not an espDNS release";
    for (int i = 80; i < REL_MANIFEST_LEN; i++)
        if (hdr[i])
            return "unsupported manifest (reserved bytes set)";
    if (memchr(hdr + 16, 0, 16) == NULL)
        return "malformed board name";
    m->kind = hdr[8];
    m->key_id = hdr[9];
    if (m->kind == 0 || m->kind >= REL_KIND_END)
        return "unknown release kind";
    if (m->key_id >= REL_NKEYS || !t->keys[m->key_id])
        return "unknown signing key";

    /* Signature first: nothing below is trusted, or reported on, until it passes. */
    if (!sig_ok(t->keys[m->key_id], hdr, REL_MANIFEST_LEN, hdr + REL_MANIFEST_LEN))
        return "bad signature";

    memcpy(m->target, hdr + 10, 6);
    memcpy(m->board, hdr + 16, 16);
    m->seq = rd64le(hdr + 32);
    m->payload_len = rd64le(hdr + 40);
    memcpy(m->sha256, hdr + 48, 32);

    if (memcmp(m->target, t->node_id, 6) != 0 && memcmp(m->target, ANY_NODE, 6) != 0)
        return "release is for another node";
    if (strcmp(m->board, t->board) != 0 && !(t->board_alt && strcmp(m->board, t->board_alt) == 0))
        return "release is for another chip image";
    if (m->seq <= last_seq)
        return "stale release (seq not above the last one applied)";
    if (m->seq > max_seq)
        return rel_why_ahead;
    return NULL;
}

static uint64_t add_sat(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }

uint64_t rel_seq_limit(bool synced, uint64_t now_ms)
{
    return synced ? add_sat(now_ms, REL_SEQ_AHEAD_MS) : UINT64_MAX;
}

const char *rel_kind_name(uint8_t kind)
{
    switch (kind) {
    case REL_FIRMWARE: return "firmware";
    case REL_CONFIG: return "config";
    case REL_ZONES: return "zones";
    case REL_BLOCKLIST: return "blocklist";
    case REL_OVERRIDES: return "overrides";
    case REL_CONTROL: return "control";
    default: return "unknown";
    }
}
