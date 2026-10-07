/*
 * Bench build only (`make bench-ota`): POST /bench runs the blocklist benchmark
 * (tests/bench_blocklist.c) on this node, next to live DNS, and returns the results.
 *
 * Body: u32 little-endian list length, the list file (blockbench -write), then query names,
 * one per line. A bench build never confirms itself: it rolls back to the previous
 * firmware on its own (ota.c), so it can be pushed to a production node.
 */
#ifdef DNS2_BENCH_BLOCKLIST

#include "bench_http.h"

#include <stdio.h>
#include <string.h>

#include "bench_blocklist.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "ota.h"

static const char *TAG = "bench";

#define OUT_CAP     (16 * 1024)
#define QUERIES     20000
#define MAX_BODY    (8 * 1024 * 1024)

double bench_now(void) { return esp_timer_get_time() * 1e-6; }

void *bench_index_alloc(size_t n) { return heap_caps_aligned_alloc(8, n ? n : 8, MALLOC_CAP_INTERNAL); }

typedef struct {
    const uint8_t *body;
    size_t len;
    char *out;
    int rc;
    SemaphoreHandle_t done;
} job_t;

static void bench_task(void *arg)
{
    job_t *j = arg;
    uint32_t ll;
    memcpy(&ll, j->body, 4);
    FILE *f = fmemopen(j->out, OUT_CAP - 1, "w");
    if (!f) {
        j->rc = -1;
    } else if (ll > j->len - 4) {
        fprintf(f, "list length %lu is past the end of the body\n", (unsigned long)ll);
        j->rc = 1;
        fclose(f);
    } else {
        fprintf(f, "node: %s, internal free %u KB, PSRAM free %u KB\n", CONFIG_IDF_TARGET,
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024));
        j->rc = bench_run(f, j->body + 4, ll, (const char *)j->body + 4 + ll, j->len - 4 - ll, QUERIES);
        fclose(f);
    }
    xSemaphoreGive(j->done);
    vTaskDelete(NULL);
}

esp_err_t bench_post(httpd_req_t *req)
{
    size_t len = req->content_len;
    if (len < 4 + BL_HEADER || len > MAX_BODY) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "body: u32 list length, list, query names\n");
    }
    /* 4 bytes in, so the list after the length is 8-aligned, as bl_open wants. */
    uint8_t *buf = heap_caps_aligned_alloc(8, len + 4, MALLOC_CAP_SPIRAM), *body = buf + 4;
    char *out = heap_caps_calloc(1, OUT_CAP, MALLOC_CAP_SPIRAM);
    if (!buf || !out) {
        free(buf);
        free(out);
        httpd_resp_set_status(req, "507 Insufficient Storage");
        return httpd_resp_sendstr(req, "no room in PSRAM\n");
    }
    /* Within the request's deadline (ota.c, httpguard.h), never retried past it */
    for (size_t got = 0; got < len;) {
        int r = httpd_req_recv(req, (char *)body + got, len - got);
        if (r <= 0) {
            free(buf);
            free(out);
            return ESP_FAIL;
        }
        got += (size_t)r;
    }
    ESP_LOGW(TAG, "running the blocklist benchmark on %u bytes", (unsigned)len);
    /* Its own task: a bigger stack than httpd's, and below the DNS tasks' priority. */
    job_t j = { .body = body, .len = len, .out = out, .done = xSemaphoreCreateBinary() };
    if (!j.done || xTaskCreate(bench_task, "bench", 16384, &j, 1, NULL) != pdPASS) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "could not start the benchmark\n");
    } else {
        xSemaphoreTake(j.done, portMAX_DELAY);
        ESP_LOGW(TAG, "benchmark done (%d)", j.rc);
        ota_http_reply(req);
        if (j.rc)
            httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "text/markdown");
        httpd_resp_sendstr(req, out);
    }
    if (j.done)
        vSemaphoreDelete(j.done);
    free(buf);
    free(out);
    return ESP_OK;
}

#endif
