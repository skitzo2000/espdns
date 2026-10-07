/*
 * GET /metrics (docs/design.md, Observability): the node's counters and gauges in the
 * Prometheus text format (metrics.h), every name prefixed espdns_. Open, as /health is: it
 * holds no name a client looked up (zone names and forwarder addresses are the config's),
 * so existing monitoring can scrape the nodes with the controller off.
 *
 * What it reads is what /status reports, from where it is kept: the DNS counters
 * (server.c), the results, rcodes and latencies (querylog.c, stats.h), the forwarders, the
 * cache, the lists, the zones, each service's state and memory, the memory plan's pools,
 * health, the release seqs, the clock and the query log. Heap and PSRAM free are what the
 * heap says now: observed, never used to size anything. The reply is sent in chunks from a
 * 4 KB buffer, so its length costs nothing.
 */
#pragma once

#include "esp_http_server.h"

/* GET /metrics (ota.c serves it, after its Host check). */
esp_err_t metrics_get(httpd_req_t *req);
