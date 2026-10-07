#include "registry.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "settings.h"

/* The zones come from settings(), which only change them with a reboot. */
static zslot_t *s_slots;
static fzone_t *s_fzones;
static int s_nslots, s_nfzones;
static hz_set_t *s_hosted;
static pthread_rwlock_t s_lock = PTHREAD_RWLOCK_INITIALIZER;

void reg_init(void)
{
    const cfg_t *c = settings();
    s_slots = calloc((size_t)c->nzones + 1, sizeof(zslot_t));
    s_fzones = calloc((size_t)c->nfzones + 1, sizeof(fzone_t));
    if (!s_slots || !s_fzones)
        abort(); /* at boot, a few KB */
    s_nslots = c->nzones;
    s_nfzones = c->nfzones;
    for (int i = 0; i < s_nslots; i++) {
        zslot_t *s = &s_slots[i];
        memset(s, 0, sizeof(*s));
        s->name = c->zones[i];
        s->apex_len = dns_name_from_str(s->name, s->apex);
    }
    for (int i = 0; i < s_nfzones; i++) {
        fzone_t *f = &s_fzones[i];
        f->name = c->fzones[i].zone;
        f->apex_len = dns_name_from_str(f->name, f->apex);
        f->forwarder = c->fzones[i].forwarder;
    }
}

int      reg_nslots(void) { return s_nslots; }
zslot_t *reg_slot(int i) { return &s_slots[i]; }
int      reg_nfzones(void) { return s_nfzones; }
fzone_t *reg_fzone(int i) { return &s_fzones[i]; }

void reg_rdlock(void) { pthread_rwlock_rdlock(&s_lock); }
void reg_wrlock(void) { pthread_rwlock_wrlock(&s_lock); }
void reg_unlock(void) { pthread_rwlock_unlock(&s_lock); }

route_t reg_route(const uint8_t *name, int len)
{
    route_t r = { ROUTE_DEFAULT, -1, NULL, false };
    int best = -1;

    for (int i = 0; i < reg_nslots(); i++) {
        zslot_t *s = &s_slots[i];
        if (s->apex_len > best && dns_name_under(name, len, s->apex, s->apex_len)) {
            best = s->apex_len;
            r.kind = (s->z && !s->expired) ? ROUTE_AUTH : ROUTE_AUTH_FAIL;
            r.idx = i;
            r.z = r.kind == ROUTE_AUTH ? s->z : NULL;
        }
    }
    zone_t *h = hz_find(s_hosted, name, len);
    if (h && h->apex_len > best) {
        best = h->apex_len;
        r = (route_t){ ROUTE_AUTH, -1, h, true };
    }
    for (int i = 0; i < reg_nfzones(); i++) {
        fzone_t *f = &s_fzones[i];
        if (f->apex_len > best && dns_name_under(name, len, f->apex, f->apex_len)) {
            best = f->apex_len;
            r = (route_t){ ROUTE_FWD_ZONE, i, NULL, false };
        }
    }
    return r;
}

zone_t *reg_find_auth(void *ctx, const uint8_t *name, int len)
{
    (void)ctx;
    route_t r = reg_route(name, len);
    return r.kind == ROUTE_AUTH ? r.z : NULL;
}

zone_t *reg_swap(int i, zone_t *nz)
{
    reg_wrlock();
    zone_t *old = s_slots[i].z;
    s_slots[i].z = nz;
    s_slots[i].expired = false;
    reg_unlock();
    return old;
}

const hz_set_t *reg_hosted(void) { return s_hosted; }

hz_set_t *reg_hosted_swap(hz_set_t *s)
{
    reg_wrlock();
    hz_set_t *old = s_hosted;
    s_hosted = s;
    reg_unlock();
    return old;
}
