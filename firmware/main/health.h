/*
 * Node health (docs/design.md, Health and fault indication): one state from every source,
 * the reasons behind it, and the LED pattern that shows it. Only the services the node
 * config enables count (svc.h): a node with no zones, no blocking or no forwarders is
 * healthy when what it does run is fine. Portable: the decision and the
 * patterns run on the host in the tests; health_node.c gathers the inputs on the node,
 * serves them and drives the LED.
 */
#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "svc.h"

typedef enum {
    HEALTH_BOOTING,    /* before the node first answers */
    HEALTH_HEALTHY,    /* everything its config enables is running */
    HEALTH_DEGRADED,   /* answering, but something enabled failed */
    HEALTH_NO_NETWORK, /* link down or no address */
    HEALTH_FAULT,      /* the listeners failed or stalled (a refused config always has the firmware defaults) */
    HEALTH_UPDATING,   /* receiving a release */
    HEALTH_NSTATES
} health_state_t;

/* Why, as bits; a state can have several. */
enum {
    HR_LISTENERS = 1u << 0,   /* fault: a DNS listener could not open */
    HR_NO_LINK = 1u << 1,     /* no network: link down */
    HR_NO_ADDRESS = 1u << 2,  /* no network: link up, no address yet */
    HR_SD = 1u << 3,          /* degraded: the board has an SD slot; no card, or it failed or timed out */
    HR_BLOCKING = 1u << 4,    /* degraded: an installed list or the overrides failed, or sector read errors */
    HR_ZONE_EXPIRED = 1u << 5, /* degraded: a secondary zone passed its SOA EXPIRE */
    HR_ZONE_REFRESH = 1u << 6, /* degraded: a secondary zone keeps failing to refresh */
    HR_UPSTREAM = 1u << 7,    /* degraded: the default forwarders aren't answering */
    HR_LOW_MEMORY = 1u << 8,  /* degraded: internal RAM nearly gone */
    HR_BOARD = 1u << 9,       /* degraded: no usable board definition (no Ethernet, no SD) */
    HR_CONFIG = 1u << 10,     /* degraded: the stored config isn't in use (refused, unreadable, failed
                               * its trial): the node runs on an older one or the firmware defaults */
    HR_CONFIG_TRIAL = 1u << 11, /* not degraded: a config with a new address waits to be reached */
    HR_HOSTED = 1u << 12,     /* degraded: installed hosted zones failed to load, or one isn't served */
    HR_REBOOT_PENDING = 1u << 13, /* not degraded: a release waits for a reboot (reboot.h); it serves */
    HR_STALLED = 1u << 14,    /* fault: the DNS listeners stalled, and the node stays up rather than
                               * reboot again (sup.h) */
    HR_SVC_FAILED = 1u << 15, /* degraded: a service keeps failing to start, or its task stalled (sup.h) */
    HR_SVC_RESTARTING = 1u << 16, /* not degraded: a service failed to start and is started again */
    HR_OLDER_COPY = 1u << 17, /* degraded: the newest blocklist, overrides or hosted zones bundle on
                               * the card is corrupt, unreadable or too big: an older copy runs */
    HR_FWD_STALLED = 1u << 18, /* degraded: the forward loop (fwdq.h) missed its watchdog: forwarded
                                * queries go unanswered, cached and local ones are still answered;
                                * never a reboot (sup.h) */
    HR_FWD_SLOW = 1u << 19,   /* degraded: the default forwarders are too slow for the queries
                               * the node is asked (health_fwd_slow): queries to them are shed
                               * (SERVFAIL at once), or wait long, or most go unanswered */
    HR_NBITS = 20
};
/* The reasons that make an answering node degraded. */
#define HR_DEGRADED_MASK \
    (HR_SD | HR_BLOCKING | HR_ZONE_EXPIRED | HR_ZONE_REFRESH | HR_UPSTREAM | HR_LOW_MEMORY | HR_BOARD | HR_CONFIG | \
     HR_HOSTED | HR_SVC_FAILED | HR_OLDER_COPY | HR_FWD_STALLED | HR_FWD_SLOW)

/* Thresholds. */
#define HEALTH_ZONE_FAILS        3       /* SOA checks or transfers failed in a row */
#define HEALTH_UPSTREAM_FAILS    5       /* upstream queries failed in a row... */
#define HEALTH_UPSTREAM_MS       30000   /* ...over at least this long */
/* Forwarders slow (HR_FWD_SLOW), the default forwarders only. Each threshold is a count, a
 * share or a time; what it is counted against comes from the config and the board: a query is
 * slow when it takes longer than one try's timeout (the config's upstream_timeout_ms), and a
 * group's cap is half the table (memory.fwd_pending, flight.h). Any of these: */
#define HEALTH_FWD_WINDOW_MS     30000   /* over the last this long, a query to them was shed (past
                                          * the group's cap)... */
#define HEALTH_FWD_SLOW_MIN      5       /* ...or at least this many upstream queries ended, and
                                          * more than half of them slow or unanswered */
#define HEALTH_FWD_BUSY_MS       10000   /* or they have held more than half their cap this long */
#define HEALTH_FWD_BUCKET_MS     5000    /* the window kept in buckets of this */
#define HEALTH_FWD_BUCKETS       (HEALTH_FWD_WINDOW_MS / HEALTH_FWD_BUCKET_MS)
#define HEALTH_LOW_MEMORY        (16 * 1024) /* internal RAM free, bytes */
#define HEALTH_BOOT_WINDOW_MS    15000   /* booting until this, then no network (BOOT_LIMIT_MS) */

/* The default forwarders, as health judges them; times are ms since boot. */
typedef struct {
    uint32_t fails;    /* upstream queries in a row with no answer (0 after any answer) */
    uint32_t since_ms; /* ...when the first of them ended */
    uint32_t shed;     /* queries to them shed (FLIGHT_FULL) in the last HEALTH_FWD_WINDOW_MS */
    uint32_t ended;    /* upstream queries that ended in the last HEALTH_FWD_WINDOW_MS */
    uint32_t slow;     /* ...of them, slow (longer than one try's timeout) or unanswered */
    bool busy;         /* they hold more than half their cap of the table (flight.h) */
    uint32_t busy_since_ms; /* ...since */
} health_fwd_t;

/* Whether the default forwarders are slow (HR_FWD_SLOW) at now_ms, by the thresholds above. */
bool health_fwd_slow(const health_fwd_t *f, uint32_t now_ms);

typedef struct {
    uint32_t enabled; /* svc_enabled(): the services the config runs; the reasons below
                       * count only for them (an SD card only for one that keeps data on it) */
    uint32_t uptime_ms;
    bool listen_failed; /* a DNS listener could not bind */
    bool stalled;       /* the listeners stalled, and the node stays up (sup.h) */
    bool listening;     /* UDP and TCP listeners open */
    bool answered;      /* has answered since boot (address and listeners both up once) */
    bool link, address;
    bool updating;      /* a release is being received */
    bool board_missing; /* no usable board definition */
    bool sd_slot;       /* the board has an SD slot */
    bool sd_mounted;
    bool sd_pending;    /* still mounting, within its boot timeout */
    bool blocking;      /* blocking_degraded() */
    int zones_expired, zones_failing;
    health_fwd_t fwd;   /* the default forwarders (health_upstream_get, flight_counts) */
    bool fwd_stalled;   /* the forward loop missed its watchdog (supervisor_fwd_stalled) */
    uint32_t heap_free; /* internal RAM, bytes */
    bool config_error;  /* settings_error() */
    bool config_trial;  /* settings_on_trial() */
    bool hosted;        /* hosted_degraded() */
    bool reboot_pending; /* ota_reboot_reasons() != 0 */
    uint32_t svc_failed;     /* services (SVC_BITs) failing (sup_svc_failed), or whose task stalled */
    uint32_t svc_restarting; /* services failing fewer times than that (sup_svc_restarting) */
    uint32_t older;          /* services (SVC_BITs: blocking, hosted) whose boot fell back to an
                              * older copy than the newest they took (blocking_older, hosted_older) */
} health_in_t;

typedef struct {
    health_state_t state;
    uint32_t reasons;
} health_t;

health_t health_compute(const health_in_t *in);
/* ---- the default forwarders: their run of failures, their sheds, their slow queries ----
 *
 * Each upstream query to the default forwarders that ends (a flight, flight.h: one however
 * many queries waited on it) is noted, answered or not and slow or not, by the DNS worker that
 * ends it; each query to them shed (FLIGHT_FULL) by the worker that asked. Any worker may, at
 * once, and health and /metrics read it from other tasks: under its lock, so a reader always
 * sees a run's count with that run's start. The last HEALTH_FWD_WINDOW_MS of queries ended
 * and queries shed are kept in HEALTH_FWD_BUCKETS buckets: the window read is that long,
 * give or take a bucket. A count, not the time of the last one: a time compared with a signed
 * difference would read as recent again once the ms clock is 2^31 past it (24.8 days). */
typedef struct {
    uint32_t epoch;        /* now_ms / HEALTH_FWD_BUCKET_MS of what it counts */
    uint16_t ended, slow, shed;
} health_fwd_bucket_t;

typedef struct {
    pthread_mutex_t lock;
    uint32_t fails;    /* upstream queries in a row with no answer (0 after any answer) */
    uint32_t since_ms; /* ...when the first of them ended */
    health_fwd_bucket_t win[HEALTH_FWD_BUCKETS];
} health_upstream_t;

void health_upstream_init(health_upstream_t *u);
/* One upstream query ended at now_ms: answered (any answer, SERVFAIL too), or not; slow: it
 * took longer than one try's timeout. */
void health_upstream_note(health_upstream_t *u, bool answered, bool slow, uint32_t now_ms);
/* A query to them was shed at now_ms. */
void health_upstream_shed(health_upstream_t *u, uint32_t now_ms);
/* Everything starts over (forwarding turned on). */
void health_upstream_reset(health_upstream_t *u);
/* What is noted, at now_ms: f's run of failures, sheds and window. busy is the table's
 * (flight_counts): set to not busy, for the caller to fill. It starts over the buckets out
 * of the window: health reads it every tick, so none is still there when the ms clock comes
 * round to it again (49.7 days). */
void health_upstream_get(health_upstream_t *u, uint32_t now_ms, health_fwd_t *f);

/* The states that answer DNS: healthy, degraded, updating. /health is 200 for them, else 503. */
bool health_answering(health_state_t s);
const char *health_state_name(health_state_t s);
/* A reason bit's name, as /health lists it ("sd card", "blocking", ...). */
const char *health_reason_name(uint32_t bit);
/* "state":"...","answering":true,"reasons":[...] (no braces). Returns the bytes written. */
size_t health_json(const health_t *h, char *j, size_t cap);

/* ---- LED patterns ---- */

/* One period: the LED is on during each [on, off) window (ms from the period's start), in
 * colour r,g,b where the LED has colour. period 0 with a window: on solid; no window: off. */
typedef struct {
    const char *name;
    uint16_t period_ms;
    uint8_t n;
    uint16_t win[3][2];
    uint8_t r, g, b;
} led_pattern_t;

/* The pattern for a state; identify (from the controller) overrides every state. */
const led_pattern_t *led_pattern(health_state_t s, bool identify);
/* Whether the LED is on t ms into the pattern. */
bool led_pattern_on(const led_pattern_t *p, uint32_t t);
/* Ms from t until the LED next changes; UINT32_MAX if it never does. */
uint32_t led_pattern_next(const led_pattern_t *p, uint32_t t);
