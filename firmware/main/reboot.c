#include "reboot.h"

#include <stdio.h>

void rb_update(rb_state_t *s, uint32_t mask, uint32_t set, uint32_t now_s)
{
    uint32_t r = (s->reasons & ~mask) | (set & mask);
    if (!s->reasons && r)
        s->since_s = now_s;
    if (!r)
        s->since_s = 0;
    s->reasons = r;
}

static const char *const REASON_NAME[RB_NBITS] = {
    "config: address", "config: wifi", "config: zones", "blocklist: size", "firmware",
};

const char *rb_reason_name(uint32_t bit)
{
    for (int i = 0; i < RB_NBITS; i++)
        if (bit == 1u << i)
            return REASON_NAME[i];
    return "unknown";
}

size_t rb_json(const rb_state_t *s, uint32_t now_s, char *j, size_t cap)
{
    if (!cap)
        return 0;
    size_t n = (size_t)snprintf(j, cap, "\"reboot\":{\"pending\":%s,\"reasons\":[", s->reasons ? "true" : "false");
    bool first = true;
    for (int i = 0; i < RB_NBITS && n < cap; i++)
        if (s->reasons & (1u << i)) {
            n += (size_t)snprintf(j + n, cap - n, "%s\"%s\"", first ? "" : ",", REASON_NAME[i]);
            first = false;
        }
    /* Signed difference: the seconds clock doesn't wrap in practice, but a time read before
     * the state was set must not come out huge. */
    int32_t age = s->reasons ? (int32_t)(now_s - s->since_s) : 0;
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "],\"since_s\":%lu}", (unsigned long)(age > 0 ? age : 0));
    return n < cap ? n : cap - 1;
}

const char *rb_ctl_parse(const uint8_t *p, size_t n, rb_ctl_t *out)
{
    if (n < 1 || p[0] != RB_CTL_REBOOT)
        return "not a reboot command";
    if (n != 5 && n != 6)
        return "bad reboot payload: 04, u32 delay_ms, optional u8 flags";
    uint32_t d = p[1] | (uint32_t)p[2] << 8 | (uint32_t)p[3] << 16 | (uint32_t)p[4] << 24;
    if (d > RB_DELAY_MAX_MS)
        return "reboot delay over 60000 ms";
    uint8_t f = n == 6 ? p[5] : 0;
    if (f & ~RB_FLAG_IF_PENDING)
        return "unknown reboot flags";
    out->delay_ms = d;
    out->flags = f;
    return NULL;
}
