/*
 * DNS wire format: names, headers, resource records, and a response builder
 * with owner-name compression. Portable C, no ESP-IDF dependencies.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNS_MAX_NAME 255
#define DNS_HDR_LEN  12

enum {
    DNS_T_A = 1, DNS_T_NS = 2, DNS_T_CNAME = 5, DNS_T_SOA = 6, DNS_T_PTR = 12,
    DNS_T_MX = 15, DNS_T_TXT = 16, DNS_T_AAAA = 28, DNS_T_SRV = 33, DNS_T_DNAME = 39,
    DNS_T_OPT = 41, DNS_T_RRSIG = 46, DNS_T_NSEC = 47, DNS_T_NSEC3 = 50, DNS_T_IXFR = 251, DNS_T_AXFR = 252, DNS_T_ANY = 255, DNS_T_CAA = 257,
};
enum { DNS_C_IN = 1 };
enum { DNS_OP_QUERY = 0, DNS_OP_NOTIFY = 4 };
enum {
    DNS_R_NOERROR = 0, DNS_R_FORMERR = 1, DNS_R_SERVFAIL = 2, DNS_R_NXDOMAIN = 3,
    DNS_R_NOTIMP = 4, DNS_R_REFUSED = 5, DNS_R_NOTAUTH = 9,
};

#define DNS_F_QR 0x8000
#define DNS_F_AA 0x0400
#define DNS_F_TC 0x0200
#define DNS_F_RD 0x0100
#define DNS_F_RA 0x0080
#define DNS_F_AD 0x0020
#define DNS_F_CD 0x0010
#define DNS_OPCODE(f) (((f) >> 11) & 0xF)
#define DNS_RCODE(f)  ((f) & 0xF)

#define DNS_EDNS_SIZE 1232 /* DNS flag day 2020 default */

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* ---- names (uncompressed wire form, including the terminating 0) ---- */

/* Read a possibly compressed name at msg[*off]; *off moves past it. Returns length or -1. */
int  dns_name_read(const uint8_t *msg, size_t len, size_t *off, uint8_t out[DNS_MAX_NAME]);
int  dns_name_skip(const uint8_t *msg, size_t len, size_t *off);
void dns_name_lower(uint8_t *name, int len);
bool dns_name_eq(const uint8_t *a, int alen, const uint8_t *b, int blen);
/* True when name equals parent or is below it. */
bool dns_name_under(const uint8_t *name, int len, const uint8_t *parent, int plen);
/* Offset of the parent name (strip first label); -1 for the root. */
int  dns_name_parent(const uint8_t *name, int len);
int  dns_name_from_str(const char *s, uint8_t out[DNS_MAX_NAME]);
/* For logs and JSON: bytes other than printable ASCII, '"' and '\\' show as '?'. */
void dns_name_to_str(const uint8_t *name, char *out, size_t outlen);

/* ---- messages ---- */

typedef struct {
    uint16_t id, flags, qd, an, ns, ar;
} dns_hdr_t;

bool dns_hdr_parse(const uint8_t *m, size_t len, dns_hdr_t *h);

typedef struct {
    uint8_t  name[DNS_MAX_NAME];
    int      name_len;
    uint16_t type, cls;
    uint32_t ttl;
    uint16_t rdlen;
    size_t   rdata_off; /* offset of rdata inside the message */
    size_t   ttl_off;   /* offset of the TTL field inside the message */
} dns_rr_view_t;

bool dns_rr_parse(const uint8_t *msg, size_t len, size_t *off, dns_rr_view_t *rr);

/* Copy rdata with embedded names decompressed (NS, CNAME, PTR, DNAME, MX, SOA, SRV).
 * Returns rdata length or -1. */
int dns_rdata_expand(const uint8_t *msg, size_t len, const dns_rr_view_t *rr,
                     uint8_t *out, size_t cap);

typedef struct {
    uint16_t id, flags;
    uint8_t  qname[DNS_MAX_NAME]; /* case preserved, as sent */
    int      qname_len;
    uint16_t qtype, qclass;
    size_t   q_end;               /* offset just past the question */
    bool     has_edns;
    uint16_t edns_size;
    uint8_t  edns_version;
    bool     do_bit;
} dns_query_t;

/* Returns DNS_R_NOERROR or DNS_R_FORMERR. Exactly one question is required. */
int dns_query_parse(const uint8_t *m, size_t len, dns_query_t *q);

/* ---- response builder ---- */

#define DNSB_CTAB 64

typedef struct {
    uint8_t *buf;
    size_t   cap, len, limit;
    size_t   q_end;     /* end of the question section */
    bool     truncated;
    uint16_t opt_size;  /* non-zero: OPT is appended by dnsb_finish */
    bool     opt_do;    /* echo the DO bit (RFC 3225) */
    uint16_t an, ns, ar;
    int      section;  /* 0 answer, 1 authority, 2 additional */
    int      nctab;
    struct {
        uint16_t       off;
        const uint8_t *name; /* points into pool */
        uint8_t        len;
    } ctab[DNSB_CTAB];
    size_t  pool_len;
    uint8_t pool[2048];      /* private copies of names, so callers' buffers can be temporary */
} dns_builder_t;

enum { DNSB_ANSWER = 0, DNSB_AUTHORITY = 1, DNSB_ADDITIONAL = 2 };

/* Starts a response: header + the client's question (copied verbatim). */
void dnsb_init(dns_builder_t *b, uint8_t *buf, size_t cap, size_t limit,
               const dns_query_t *q, uint16_t flags);
/* Adds one RR. Returns false (and marks truncated) when it would exceed the limit. */
bool dnsb_rr(dns_builder_t *b, int section, const uint8_t *owner, int owner_len,
             uint16_t type, uint16_t cls, uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);
/* Requests an OPT record (advertising udp_size, echoing DO) at the end of the response.
 * Call before adding RRs so its space is reserved. */
void dnsb_opt(dns_builder_t *b, uint16_t udp_size, bool do_bit);
void dnsb_set_rcode(dns_builder_t *b, int rcode);
void dnsb_set_flags(dns_builder_t *b, uint16_t set, uint16_t clear);
/* Writes section counts. On truncation, drops all RRs and sets TC. Returns length. */
size_t dnsb_finish(dns_builder_t *b);

/* Copies the RRs of an upstream response (except OPT) into b, subtracting age from TTLs.
 * answers_only: copy just the answer section (used to extend a local CNAME chain).
 * dnssec: the client set DO. Without it the DNSSEC records (RRSIG, NSEC, NSEC3) are left
 * out, unless the question asked for that type or ANY (RFC 4035, 3.2.1): every upstream
 * query asks with DO, so one cached answer serves clients with and without it (cache.h).
 * Returns the upstream rcode, or -1 if the message is malformed. */
int dnsb_relay(dns_builder_t *b, const uint8_t *m, size_t len, uint32_t age, bool answers_only, bool dnssec);

/* Cacheable lifetime of a response (RFC 2308 for negatives); 0 = do not cache. */
uint32_t dns_resp_ttl(const uint8_t *m, size_t len);

/* Minimal error/empty response straight from a query buffer. Returns length. */
size_t dns_make_error(const dns_query_t *q, uint8_t *out, size_t cap, int rcode, uint16_t extra_flags);
