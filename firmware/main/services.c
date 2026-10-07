#include "services.h"

#include "blocking.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "hosted.h"
#include "querylog.h"
#include "registry.h"
#include "server.h"
#include "settings.h"
#include "share.h"
#include "xfr.h"

static const char *TAG = "services";

/* One change at a time: a config applied live and the supervisor's restart of a service
 * whose start failed. Without it a restart that saw the service on could start it just
 * after the live config stopped it. */
static StaticSemaphore_t s_lock_buf;
static SemaphoreHandle_t s_lock;

void services_init(void) { s_lock = xSemaphoreCreateMutexStatic(&s_lock_buf); }

static void lock(void)
{
    if (s_lock)
        xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void unlock(void)
{
    if (s_lock)
        xSemaphoreGive(s_lock);
}

typedef struct {
    void (*start)(void); /* NULL: nothing to start (no task or memory of its own) */
    void (*stop)(void);  /* NULL: nothing to stop, or not live (a reboot) */
    svc_state_t (*state)(void);
    bool (*broken)(void); /* NULL: its start can't fail on its own */
    size_t (*held)(void); /* what it holds now, bytes; NULL: what share.h counted */
} ops_t;

/* Forwarding has no task or buffers of its own: the DNS workers ask the forwarders while
 * there are any (server.c), and the cache belongs to the dns service. */
static svc_state_t forwarding_state(void) { return settings()->nfwd ? SVC_RUNNING : SVC_OFF; }
static svc_state_t fzones_state(void) { return reg_nfzones() ? SVC_RUNNING : SVC_OFF; }
static void hosted_start_live(void) { hosted_start(false); }

/* In the boot order app_main follows; the zone services change only with a reboot. */
static const ops_t OPS[SVC_N] = {
    [SVC_DNS] = { server_start, NULL, server_state, NULL, NULL },
    [SVC_FORWARDING] = { server_upstream_reset, NULL, forwarding_state, NULL, NULL },
    [SVC_FORWARD_ZONES] = { NULL, NULL, fzones_state, NULL, NULL },
    [SVC_SECONDARY] = { xfr_start, NULL, xfr_state, xfr_broken, xfr_held },
    [SVC_HOSTED] = { hosted_start_live, hosted_stop, hosted_state, hosted_broken, hosted_held },
    [SVC_BLOCKING] = { blocking_start, blocking_stop, blocking_state, blocking_broken, NULL },
    [SVC_QUERYLOG] = { querylog_start, querylog_stop, querylog_state, querylog_broken, NULL },
};

void services_apply(uint32_t before, uint32_t after)
{
    uint32_t stop, start;
    svc_changes(before, after, &stop, &start);
    lock();
    for (int i = 0; i < SVC_N; i++)
        if (stop & SVC_BIT(i)) {
            ESP_LOGI(TAG, "%s: off", svc_name(i));
            if (OPS[i].stop)
                OPS[i].stop();
        }
    /* The plan for what runs now: checked when the config was pushed (settings.c). */
    share_set_plan(after);
    for (int i = 0; i < SVC_N; i++)
        if (start & SVC_BIT(i)) {
            ESP_LOGI(TAG, "%s: on", svc_name(i));
            if (OPS[i].start)
                OPS[i].start();
        }
    unlock();
}

bool services_broken(int svc) { return (unsigned)svc < SVC_N && OPS[svc].broken && OPS[svc].broken(); }

void services_restart(int svc)
{
    if ((unsigned)svc >= SVC_N || !OPS[svc].start)
        return;
    lock();
    /* Still on in the config that runs, and still broken: a live config may have changed
     * either since the supervisor looked. */
    if ((svc_enabled(settings()) & SVC_BIT(svc)) && services_broken(svc))
        OPS[svc].start();
    unlock();
}

void services_snapshot(svc_state_t st[SVC_N], size_t planned[SVC_N], size_t held[SVC_N])
{
    const mp_plan_t *p = share_plan();
    for (int i = 0; i < SVC_N; i++) {
        st[i] = OPS[i].state();
        planned[i] = mp_share(p, i);
        held[i] = OPS[i].held ? OPS[i].held() : share_used(i, MP_INTERNAL) + share_used(i, MP_PSRAM);
    }
}

size_t services_status_json(char *j, size_t cap)
{
    svc_state_t st[SVC_N];
    size_t planned[SVC_N], held[SVC_N];
    services_snapshot(st, planned, held);
    return svc_json(st, planned, held, j, cap);
}
