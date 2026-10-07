#include "health.h"

#include <stdio.h>

health_t health_compute(const health_in_t *in)
{
    health_t h = { HEALTH_HEALTHY, 0 };
    if (in->listen_failed)
        h.reasons |= HR_LISTENERS;
    if (in->stalled)
        h.reasons |= HR_STALLED;
    if (!in->link)
        h.reasons |= HR_NO_LINK;
    else if (!in->address)
        h.reasons |= HR_NO_ADDRESS;
    if (in->board_missing)
        h.reasons |= HR_BOARD;
    /* Only what the config runs counts: a service that is off can't fail. */
    uint32_t on = in->enabled;
    /* A card still mounting within its boot timeout isn't a fault yet; a timed-out one is.
     * Without a service that keeps data on it, the node doesn't need one. */
    if ((on & SVC_SD) && in->sd_slot && !in->sd_mounted && !in->sd_pending)
        h.reasons |= HR_SD;
    if ((on & SVC_BIT(SVC_BLOCKING)) && in->blocking)
        h.reasons |= HR_BLOCKING;
    if ((on & SVC_BIT(SVC_SECONDARY)) && in->zones_expired)
        h.reasons |= HR_ZONE_EXPIRED;
    if ((on & SVC_BIT(SVC_SECONDARY)) && in->zones_failing)
        h.reasons |= HR_ZONE_REFRESH;
    /* One slow name isn't the forwarders failing: a run of failures over half a minute is. */
    /* Signed difference: wraps with the ms clock (49 days), and a run that started just after
     * uptime_ms was read comes out negative. */
    if ((on & SVC_BIT(SVC_FORWARDING)) && in->fwd.fails >= HEALTH_UPSTREAM_FAILS &&
        (int32_t)(in->uptime_ms - in->fwd.since_ms) >= HEALTH_UPSTREAM_MS)
        h.reasons |= HR_UPSTREAM;
    /* Answering, but not fast enough for what the node is asked: queries are shed, or wait
     * long, or most of them get no answer in time (#60). */
    if ((on & SVC_BIT(SVC_FORWARDING)) && health_fwd_slow(&in->fwd, in->uptime_ms))
        h.reasons |= HR_FWD_SLOW;
    if (in->heap_free < HEALTH_LOW_MEMORY)
        h.reasons |= HR_LOW_MEMORY;
    if (in->config_error)
        h.reasons |= HR_CONFIG;
    if ((on & SVC_BIT(SVC_HOSTED)) && in->hosted)
        h.reasons |= HR_HOSTED;
    if (in->config_trial)
        h.reasons |= HR_CONFIG_TRIAL;
    if (in->reboot_pending)
        h.reasons |= HR_REBOOT_PENDING;
    if (in->older & on)
        h.reasons |= HR_OLDER_COPY;
    /* The forward loop asks for the default forwarders and the forward zones alike. */
    if ((on & (SVC_BIT(SVC_FORWARDING) | SVC_BIT(SVC_FORWARD_ZONES))) && in->fwd_stalled)
        h.reasons |= HR_FWD_STALLED;
    if (in->svc_failed & on)
        h.reasons |= HR_SVC_FAILED;
    else if (in->svc_restarting & on)
        h.reasons |= HR_SVC_RESTARTING;

    bool network = in->link && in->address;
    if (in->listen_failed || in->stalled)
        h.state = HEALTH_FAULT;
    else if (!in->listening || (!in->answered && !network && in->uptime_ms < HEALTH_BOOT_WINDOW_MS))
        h.state = HEALTH_BOOTING;
    else if (!network)
        h.state = HEALTH_NO_NETWORK;
    else if (in->updating)
        h.state = HEALTH_UPDATING;
    else if (h.reasons & HR_DEGRADED_MASK)
        h.state = HEALTH_DEGRADED;
    return h;
}

bool health_answering(health_state_t s) { return s == HEALTH_HEALTHY || s == HEALTH_DEGRADED || s == HEALTH_UPDATING; }

static const char *const STATE_NAME[HEALTH_NSTATES] = { "booting", "healthy", "degraded", "no network", "fault", "updating" };

const char *health_state_name(health_state_t s) { return (unsigned)s < HEALTH_NSTATES ? STATE_NAME[s] : "unknown"; }

static const char *const REASON_NAME[HR_NBITS] = {
    "listeners failed", "no link", "no address", "sd card", "blocking", "zone expired",
    "zone refresh failing", "forwarders failing", "low memory", "no board definition", "config",
    "config on trial", "hosted zones", "reboot pending", "listeners stalled", "service failed",
    "service restarting", "older copy", "forwarder task stalled", "forwarders slow",
};

bool health_fwd_slow(const health_fwd_t *f, uint32_t now_ms)
{
    /* A signed difference: it wraps with the ms clock, and a time noted just after now_ms was
     * read comes out negative (it counts as now). */
    if (f->shed)
        return true;
    if (f->busy && (int32_t)(now_ms - f->busy_since_ms) >= HEALTH_FWD_BUSY_MS)
        return true;
    return f->ended >= HEALTH_FWD_SLOW_MIN && f->slow * 2 > f->ended;
}

void health_upstream_init(health_upstream_t *u)
{
    pthread_mutex_init(&u->lock, NULL);
    health_upstream_reset(u);
}

/* now_ms's bucket, started over if it held an older one (under the lock). */
static health_fwd_bucket_t *bucket(health_upstream_t *u, uint32_t now_ms)
{
    uint32_t e = now_ms / HEALTH_FWD_BUCKET_MS;
    health_fwd_bucket_t *b = &u->win[e % HEALTH_FWD_BUCKETS];
    if (b->epoch != e)
        *b = (health_fwd_bucket_t){ .epoch = e };
    return b;
}

void health_upstream_note(health_upstream_t *u, bool answered, bool slow, uint32_t now_ms)
{
    pthread_mutex_lock(&u->lock);
    if (answered) {
        u->fails = 0;
    } else if (u->fails++ == 0) {
        u->since_ms = now_ms;
    }
    health_fwd_bucket_t *b = bucket(u, now_ms);
    if (b->ended < UINT16_MAX) {
        b->ended++;
        b->slow += slow || !answered;
    }
    pthread_mutex_unlock(&u->lock);
}

void health_upstream_shed(health_upstream_t *u, uint32_t now_ms)
{
    pthread_mutex_lock(&u->lock);
    health_fwd_bucket_t *b = bucket(u, now_ms);
    if (b->shed < UINT16_MAX)
        b->shed++;
    pthread_mutex_unlock(&u->lock);
}

void health_upstream_reset(health_upstream_t *u)
{
    pthread_mutex_lock(&u->lock);
    u->fails = u->since_ms = 0;
    /* No bucket's epoch is now's: each starts over when it is next used. */
    for (int i = 0; i < HEALTH_FWD_BUCKETS; i++)
        u->win[i] = (health_fwd_bucket_t){ .epoch = UINT32_MAX };
    pthread_mutex_unlock(&u->lock);
}

void health_upstream_get(health_upstream_t *u, uint32_t now_ms, health_fwd_t *f)
{
    uint32_t e = now_ms / HEALTH_FWD_BUCKET_MS;
    pthread_mutex_lock(&u->lock);
    f->fails = u->fails;
    f->since_ms = u->since_ms;
    f->ended = f->slow = f->shed = 0;
    f->busy = false; /* the table's (flight_counts): the caller's to fill */
    f->busy_since_ms = 0;
    for (int i = 0; i < HEALTH_FWD_BUCKETS; i++) {
        health_fwd_bucket_t *b = &u->win[i];
        /* This one or the ones before: the window; or the next, noted by a worker just after
         * now_ms was read (it counts as now). */
        uint32_t d = e - b->epoch;
        if (d < HEALTH_FWD_BUCKETS || d == UINT32_MAX) {
            f->ended += b->ended;
            f->slow += b->slow;
            f->shed += b->shed;
        } else if (b->epoch != UINT32_MAX) {
            /* Out of the window: started over now, not when next used. A bucket left as it is
             * would be read as in the window again once the ms clock comes round to its epoch
             * (2^32 ms, 49.7 days on, with no query meanwhile to use it); health reads the
             * window every tick, far more often than that. */
            *b = (health_fwd_bucket_t){ .epoch = UINT32_MAX };
        }
    }
    pthread_mutex_unlock(&u->lock);
}

const char *health_reason_name(uint32_t bit)
{
    for (int i = 0; i < HR_NBITS; i++)
        if (bit == 1u << i)
            return REASON_NAME[i];
    return "unknown";
}

size_t health_json(const health_t *h, char *j, size_t cap)
{
    if (!cap)
        return 0;
    size_t n = (size_t)snprintf(j, cap, "\"state\":\"%s\",\"answering\":%s,\"reasons\":[", health_state_name(h->state),
                                health_answering(h->state) ? "true" : "false");
    bool first = true;
    for (int i = 0; i < HR_NBITS && n < cap; i++)
        if (h->reasons & (1u << i)) {
            n += (size_t)snprintf(j + n, cap - n, "%s\"%s\"", first ? "" : ",", REASON_NAME[i]);
            first = false;
        }
    if (n < cap)
        n += (size_t)snprintf(j + n, cap - n, "]");
    return n < cap ? n : cap - 1;
}

/* ---- LED patterns (docs/design.md, LED patterns): told apart on a single colour LED, in
 * colour too on an RGB one. ---- */

static const led_pattern_t PATTERNS[HEALTH_NSTATES] = {
    [HEALTH_BOOTING] = { "fast blink", 200, 1, { { 0, 100 } }, 0, 0, 255 },                       /* 5 a second, blue */
    [HEALTH_HEALTHY] = { "blip", 5000, 1, { { 0, 60 } }, 0, 255, 0 },                             /* every 5 s, green */
    [HEALTH_DEGRADED] = { "double blink", 2000, 2, { { 0, 150 }, { 300, 450 } }, 255, 110, 0 },  /* amber */
    [HEALTH_NO_NETWORK] = { "slow blink", 1000, 1, { { 0, 500 } }, 255, 0, 0 },                  /* red, slow */
    [HEALTH_FAULT] = { "solid", 0, 1, { { 0, 1 } }, 255, 0, 0 },                                 /* red, solid */
    [HEALTH_UPDATING] = { "triple blink", 1000, 3, { { 0, 80 }, { 160, 240 }, { 320, 400 } }, 0, 0, 255 },
};
static const led_pattern_t IDENTIFY = { "flicker", 80, 1, { { 0, 40 } }, 255, 255, 255 }; /* 12.5 Hz, white */

const led_pattern_t *led_pattern(health_state_t s, bool identify)
{
    if (identify)
        return &IDENTIFY;
    return &PATTERNS[(unsigned)s < HEALTH_NSTATES ? s : HEALTH_FAULT];
}

bool led_pattern_on(const led_pattern_t *p, uint32_t t)
{
    if (!p->period_ms)
        return p->n > 0;
    uint32_t x = t % p->period_ms;
    for (int i = 0; i < p->n; i++)
        if (x >= p->win[i][0] && x < p->win[i][1])
            return true;
    return false;
}

uint32_t led_pattern_next(const led_pattern_t *p, uint32_t t)
{
    if (!p->period_ms)
        return UINT32_MAX;
    uint32_t x = t % p->period_ms, best = p->period_ms - x; /* the next period starts */
    for (int i = 0; i < p->n; i++)
        for (int e = 0; e < 2; e++)
            if (p->win[i][e] > x && p->win[i][e] - x < best)
                best = p->win[i][e] - x;
    return best;
}
