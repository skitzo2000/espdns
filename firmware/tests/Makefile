CFLAGS = -std=gnu17 -g -O1 -Wall -Wextra -Wno-unused-parameter -I../main \
         -fsanitize=address,undefined -fno-omit-frame-pointer
SRCS   = test_core.c ../main/dns_wire.c ../main/zone.c ../main/answer.c ../main/cache.c ../main/flight.c ../main/fwdq.c ../main/upq.c ../main/forward.c \
         ../main/release.c ../main/blocklist.c ../main/block.c ../main/board_def.c ../main/health.c ../main/cfg.c ../main/hzone.c ../main/reboot.c ../main/svc.c ../main/memplan.c ../main/sup.c ../main/cpuplan.c \
         ../main/qlog.c ../main/stats.c ../main/metrics.c $(IDF_PATH)/components/json/cJSON/cJSON.c
CFLAGS += -I$(IDF_PATH)/components/json/cJSON
# The firmware defaults as a deployment's transitional image has them: an address built in
# (make STATIC_IP=... STATIC_NETMASK=... STATIC_GATEWAY=...) and its site defaults
# (make SITE_DEFAULTS=..., here the example's), on documentation addresses (RFC 5737).
CFLAGS += -DDNS2_STATIC_IP='"192.0.2.53"' -DDNS2_NETMASK='"255.255.255.0"' -DDNS2_GATEWAY='"192.0.2.1"' \
          -DDNS2_SITE_DEFAULTS='"../site-defaults.h.example"'
# Upstream queries (forward.c) go to the tests' fake forwarders on the loopback, on a port
# that needs no privilege.
CFLAGS += -DDNS2_FWD_PORT=15353
# The project's own defaults, with nothing built in (test_defaults.c)
NEUTRAL_SRCS = test_defaults.c $(filter-out test_core.c,$(SRCS))
# The query log, /metrics and the querylog config (test_observe.c), with the same build
OBS_SRCS = test_observe.c $(filter-out test_core.c,$(SRCS))
# Local zones' lookups and zone transfers (test_zones.c), against a fake primary on the loopback
ZONES_SRCS = test_zones.c ../main/zone.c ../main/axfr.c ../main/answer.c ../main/dns_wire.c ../main/forward.c
# The node HTTP server's Host check, deadlines and JSON strings (test_http.c)
HTTP_SRCS = test_http.c ../main/httpguard.c ../main/jsonw.c $(IDF_PATH)/components/json/cJSON/cJSON.c
# The board catalog (boards/ at the top of the repo; /boards in the build container)
BOARDS ?= $(firstword $(wildcard /boards) ../../boards)
CFLAGS += -DBOARDS_DIR='"$(BOARDS)"'

# mbedTLS from the ESP-IDF tree (the same code the firmware links), with a minimal config.
MBEDTLS  = $(IDF_PATH)/components/mbedtls/mbedtls
TLS_SRCS = $(addprefix $(MBEDTLS)/library/,ecdsa.c ecp.c ecp_curves.c bignum.c bignum_core.c \
             constant_time.c platform_util.c sha256.c asn1parse.c asn1write.c)
TLS_OBJS = $(patsubst $(MBEDTLS)/library/%.c,tls/%.o,$(TLS_SRCS))
TLS_FLAGS = -std=gnu17 -O2 -I$(MBEDTLS)/include -I. -DMBEDTLS_CONFIG_FILE='"mbedtls_host_config.h"'

# The tools' tests (Python): the ESP-IDF image's Python, which has the cryptography package
# (the image's /usr/bin/python3 does not), else python3
PYTHON ?= $(or $(firstword $(wildcard $(if $(IDF_PYTHON_ENV_PATH),$(IDF_PYTHON_ENV_PATH)/bin/python) $(if $(IDF_TOOLS_PATH),$(IDF_TOOLS_PATH)/python_env/*/bin/python))),python3)

test: test_core test_defaults test_observe test_http test_zones
	./test_core
	./test_defaults
	./test_observe
	./test_http
	./test_zones
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) test_ota_push.py
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) test_containers.py
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) test_version.py

test_core: $(SRCS) $(TLS_OBJS) release_vectors.h blocklist_vectors.h memplan_vectors.json place_vectors.json cpu_vectors.json cfg_reboot_vectors.json \
           ../site-defaults.h.example config_example.json
	$(CC) $(CFLAGS) $(TLS_FLAGS:-O2=) -o $@ $(SRCS) $(TLS_OBJS) -lpthread

test_defaults: $(NEUTRAL_SRCS) $(TLS_OBJS) ../main/config.h
	$(CC) $(filter-out -DDNS2_%,$(CFLAGS)) $(TLS_FLAGS:-O2=) -o $@ $(NEUTRAL_SRCS) $(TLS_OBJS) -lpthread

test_observe: $(OBS_SRCS) $(TLS_OBJS)
	$(CC) $(CFLAGS) $(TLS_FLAGS:-O2=) -o $@ $(OBS_SRCS) $(TLS_OBJS) -lpthread

test_http: $(HTTP_SRCS) ../main/httpguard.h ../main/jsonw.h
	$(CC) $(CFLAGS) -o $@ $(HTTP_SRCS) -lpthread

# The heap the zone code holds, counted (test_zones.c)
ZONES_WRAP = -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free
test_zones: $(ZONES_SRCS) ../main/zone.h ../main/axfr.h ../main/answer.h
	$(CC) $(CFLAGS) -o $@ $(ZONES_SRCS) $(ZONES_WRAP) -lpthread

tls/%.o: $(MBEDTLS)/library/%.c mbedtls_host_config.h
	@mkdir -p tls
	$(CC) $(TLS_FLAGS) -c -o $@ $<

clean:
	rm -rf test_core test_defaults test_observe test_http test_zones bench_blocklist tls

# Lookup speed on a real list: make bench FILE=list.bin QUERIES=q.txt (see bench_blocklist.c)
bench_blocklist: bench_blocklist.c ../main/blocklist.c ../main/dns_wire.c
	$(CC) -std=gnu17 -O2 -Wall -Wextra -Wno-unused-parameter -I../main -o $@ $^

bench: bench_blocklist
	./bench_blocklist $(FILE) $(QUERIES)
