#include "jsonw.h"

#include <stdio.h>
#include <string.h>

size_t json_esc(char *out, size_t cap, const char *s)
{
    size_t o = 0;
    if (!cap)
        return 0;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        char e[8];
        size_t k;
        if (c == '"' || c == '\\') {
            e[0] = '\\', e[1] = (char)c, k = 2;
        } else if (c < 0x20 || c >= 0x7f) {
            snprintf(e, sizeof(e), "\\u%04x", c);
            k = 6;
        } else {
            e[0] = (char)c, k = 1;
        }
        if (o + k >= cap)
            break;
        memcpy(out + o, e, k);
        o += k;
    }
    out[o] = 0;
    return o;
}

const char *json_q(char *out, size_t cap, const char *s)
{
    if (cap < 5) {
        if (cap)
            out[0] = 0;
        return out;
    }
    if (!s) {
        memcpy(out, "null", 5);
        return out;
    }
    out[0] = '"';
    size_t n = 1 + json_esc(out + 1, cap - 2, s);
    out[n++] = '"';
    out[n] = 0;
    return out;
}

const char *json_qz(char *out, size_t cap, const char *s) { return json_q(out, cap, s && *s ? s : NULL); }

const char *json_mac(char *out, size_t cap, const unsigned char mac[6])
{
    static const char hex[] = "0123456789abcdef";
    if (!cap)
        return out;
    out[0] = 0;
    if (cap < 18 || !mac)
        return out;
    unsigned char any = 0;
    for (int i = 0; i < 6; i++)
        any |= mac[i];
    if (!any)
        return out;
    for (int i = 0; i < 6; i++) {
        out[3 * i] = hex[mac[i] >> 4];
        out[3 * i + 1] = hex[mac[i] & 15];
        out[3 * i + 2] = i < 5 ? ':' : 0;
    }
    return out;
}
