#include "svc.h"

#include <stdio.h>

uint32_t svc_enabled(const cfg_t *c)
{
    uint32_t on = SVC_BIT(SVC_DNS);
    if (c->nfwd)
        on |= SVC_BIT(SVC_FORWARDING);
    if (c->nfzones)
        on |= SVC_BIT(SVC_FORWARD_ZONES);
    if (c->nzones)
        on |= SVC_BIT(SVC_SECONDARY);
    if (c->hosted)
        on |= SVC_BIT(SVC_HOSTED);
    if (c->blocking)
        on |= SVC_BIT(SVC_BLOCKING);
    if (c->querylog)
        on |= SVC_BIT(SVC_QUERYLOG);
    return on;
}

void svc_changes(uint32_t before, uint32_t after, uint32_t *stop, uint32_t *start)
{
    *stop = before & ~after & SVC_LIVE;
    *start = after & ~before & SVC_LIVE;
}

static const char *const NAME[SVC_N] = { "dns", "forwarding", "forward_zones", "secondary", "hosted", "blocking",
                                         "querylog" };
static const char *const STATE[SVC_NSTATES] = { "off", "starting", "running", "failed" };

const char *svc_name(svc_id_t id) { return (unsigned)id < SVC_N ? NAME[id] : "unknown"; }

const char *svc_state_name(svc_state_t s) { return (unsigned)s < SVC_NSTATES ? STATE[s] : "unknown"; }

size_t svc_json(const svc_state_t st[SVC_N], const size_t planned[SVC_N], const size_t allocated[SVC_N], char *j,
                size_t cap)
{
    if (!cap)
        return 0;
    size_t n = (size_t)snprintf(j, cap, "\"services\":[");
    for (int i = 0; i < SVC_N && n < cap; i++)
        n += (size_t)snprintf(j + n, cap - n,
                              "%s{\"name\":\"%s\",\"state\":\"%s\",\"memory\":{\"planned\":%lu,\"allocated\":%lu}}",
                              i ? "," : "", NAME[i], svc_state_name(st[i]), (unsigned long)planned[i],
                              (unsigned long)allocated[i]);
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "]");
    return n < cap ? n : cap - 1;
}
