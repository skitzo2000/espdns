/*
 * JSON strings in the node's replies (/status, /health, a release's reply): every string
 * the node writes into JSON goes through here, so a quote, a backslash or a control
 * character in a value (an error that quotes a config, a board name, a time zone) can never
 * end the string early and break the reply, nor the controller's pushes with it.
 *
 * Escapes '"' and '\\' with a backslash, and every byte outside printable ASCII (control
 * characters, DEL, and bytes from 0x80 up, which need not be UTF-8) as \u00XX, so the result
 * is valid JSON whatever the bytes. A string too long for the room is cut short between
 * whole escapes, never inside one.
 *
 * Portable: run on the host in the tests.
 */
#pragma once

#include <stddef.h>

/* s escaped for inside a JSON string (no quotes around it) into out, NUL-terminated (cap
 * > 0). Returns its length. NULL is "". */
size_t json_esc(char *out, size_t cap, const char *s);

/* s as a JSON value into out: "\"<escaped>\"", or null for NULL; NUL-terminated (cap >= 5).
 * Returns out, for a "%s" in a format. */
const char *json_q(char *out, size_t cap, const char *s);

/* As json_q, but "" is null too (a string buffer that holds nothing). */
const char *json_qz(char *out, size_t cap, const char *s);

/* A MAC address as /status writes it ("mac": the interface's, what a DHCP reservation or a
 * static address is set by): six lower-case hex pairs with colons, "aa:bb:cc:dd:ee:ff", into
 * out (cap >= 18), or "" for none (all zero: no interface yet; or NULL). Only hex digits and
 * colons, so it is a JSON string's content as it is. Returns out, for a "%s" in a format. */
const char *json_mac(char *out, size_t cap, const unsigned char mac[6]);
