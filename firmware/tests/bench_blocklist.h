/* Blocklist benchmark core, shared by the host tool, the on-board app (bench/blocklist) and
 * the node's bench build (main/bench_http.c). */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "blocklist.h"

/* Seconds from any fixed point; the host and the board each provide it. */
double bench_now(void);

/* n bytes, 8-aligned, for bl_index_move: internal RAM on a board (freed with free()). */
void *bench_index_alloc(size_t n);

/* Times lookups in a blocklist file for up to max_queries names (one per line in qtext)
 * and writes the results to out as Markdown tables. Returns 0, or 1 on a bad file or a
 * wrong answer. */
int bench_run(FILE *out, const uint8_t *file, size_t len, const char *qtext, size_t qlen, size_t max_queries);
