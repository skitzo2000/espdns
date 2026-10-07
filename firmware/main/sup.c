#include "sup.h"

uint32_t sup_backoff_ms(uint32_t fails)
{
    uint32_t ms = SUP_BACKOFF_MIN_MS;
    for (uint32_t i = 1; i < fails && ms < SUP_BACKOFF_MAX_MS; i++)
        ms *= 2;
    return ms < SUP_BACKOFF_MAX_MS ? ms : SUP_BACKOFF_MAX_MS;
}

bool sup_svc_tick(sup_svc_t *s, bool broken, uint32_t now_ms)
{
    s->checking = false;
    if (!broken) {
        if (s->waiting) { /* it came back by itself */
            s->waiting = false;
            s->at_ms = now_ms;
        } else if (s->fails && now_ms - s->at_ms >= SUP_STABLE_MS) {
            s->fails = 0;
        }
        return false;
    }
    if (!s->waiting) { /* a new failure: the first, or the restart before didn't take */
        s->fails++;
        s->waiting = true;
        s->at_ms = now_ms + sup_backoff_ms(s->fails);
        return false;
    }
    if ((int32_t)(now_ms - s->at_ms) < 0)
        return false;
    /* Restarting: the next look sees whether it took. */
    s->waiting = false;
    s->checking = true;
    s->at_ms = now_ms;
    return true;
}

/* Between a restart and the next look it still counts as failed, so health doesn't flap. */
bool sup_svc_failed(const sup_svc_t *s) { return (s->waiting || s->checking) && s->fails >= SUP_FAILED_AFTER; }

bool sup_svc_restarting(const sup_svc_t *s)
{
    return (s->waiting || s->checking) && s->fails && s->fails < SUP_FAILED_AFTER;
}

uint32_t sup_late(const sup_watch_t *w, int n, uint32_t now_ms, bool *stalled)
{
    uint32_t late = 0;
    int workers = 0, workers_late = 0;
    *stalled = false;
    for (int i = 0; i < n; i++) {
        if (!w[i].on || w[i].role == SUP_FORWARDER)
            continue;
        bool l = !w[i].parked && now_ms - w[i].kick_ms > w[i].deadline_ms;
        if (w[i].role == SUP_WORKER) {
            workers++;
            workers_late += l;
        } else if (l && w[i].role == SUP_LISTENER) {
            *stalled = true;
        }
        if (l && w[i].svc >= 0)
            late |= 1u << w[i].svc;
    }
    if (workers && workers_late == workers)
        *stalled = true;
    return late;
}

bool sup_forwarder_late(const sup_watch_t *w, int n, uint32_t now_ms)
{
    for (int i = 0; i < n; i++)
        if (w[i].on && w[i].role == SUP_FORWARDER && !w[i].parked && now_ms - w[i].kick_ms > w[i].deadline_ms)
            return true;
    return false;
}

uint32_t sup_stall_boot(uint32_t count, bool after_watchdog) { return after_watchdog ? count + 1 : count; }

bool sup_stall_reboot(uint32_t *count)
{
    if (*count >= SUP_STALL_REBOOTS)
        return false;
    (*count)++;
    return true;
}

bool sup_stall_settled(uint32_t uptime_ms) { return uptime_ms >= SUP_STALL_WINDOW_MS; }
