/*
 * The project's own firmware defaults (main/config.h), built with nothing a deployment adds
 * (no STATIC_IP, no SITE_DEFAULTS): a node on them knows no address, no zone primary, no
 * zones and no conditional forwarders, and forwards to public resolvers. No deployment's
 * values are built into an image unless that deployment builds them in (test_core.c checks
 * the site defaults, with the example's).
 */
#include <stdio.h>
#include <string.h>

#include "cfg.h"
#include "config.h"
#include "svc.h"

static int s_fail;
#define CHECK(x)                                                     \
    do {                                                             \
        if (!(x)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
            s_fail++;                                                \
        }                                                            \
    } while (0)

int main(void)
{
    static cfg_t c;
    char err[160];
    uint32_t a;

    CHECK(!DNS2_STATIC_IP[0] && !DNS2_NETMASK[0] && !DNS2_GATEWAY[0] && !DNS2_PRIMARY[0]);
    CHECK(!strcmp(cfg_builtin_addr(), "")); /* the marker the rollout reads: no address */
    CHECK(cfg_build(&c, NULL, NULL, 0, err, sizeof(err)));
    CHECK(c.ip == 0 && !c.dhcp && c.addr_from == CFG_ADDR_NONE && !strcmp(cfg_addr_kind(&c), "none"));
    CHECK(c.primary == 0 && c.nzones == 0 && c.nfzones == 0);
    CHECK(c.nfwd == 2 && cfg_parse_ipv4("9.9.9.9", &a) && c.fwd[0] == a && cfg_parse_ipv4("149.112.112.112", &a) &&
          c.fwd[1] == a);
    CHECK(!(svc_enabled(&c) & SVC_BIT(SVC_SECONDARY)) && !(svc_enabled(&c) & SVC_BIT(SVC_FORWARD_ZONES)));
    /* A config gives what it names, as on any defaults. */
    const char *j = "{\"secondary\":{\"primary\":\"192.0.2.254\",\"zones\":[\"example.com\"]}}";
    CHECK(cfg_build(&c, NULL, j, strlen(j), err, sizeof(err)) && c.nzones == 1 && cfg_parse_ipv4("192.0.2.254", &a) &&
          c.primary == a && (svc_enabled(&c) & SVC_BIT(SVC_SECONDARY)));
    if (s_fail) {
        fprintf(stderr, "%d check(s) failed\n", s_fail);
        return 1;
    }
    printf("defaults: all tests passed\n");
    return 0;
}
