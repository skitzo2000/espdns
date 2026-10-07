/* Bench build only: POST /bench (see bench_http.c). */
#pragma once

#include "esp_http_server.h"

esp_err_t bench_post(httpd_req_t *req);
