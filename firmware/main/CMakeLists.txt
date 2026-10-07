# Public keys nodes trust for signed releases. Committed; the private halves live in secrets/.
set(RELEASE_PUB "${CMAKE_CURRENT_LIST_DIR}/../keys/release.pub")
set(RECOVERY_PUB "${CMAKE_CURRENT_LIST_DIR}/../keys/recovery.pub")
if(NOT EXISTS "${RELEASE_PUB}" OR NOT EXISTS "${RECOVERY_PUB}")
    message(FATAL_ERROR "keys/release.pub or keys/recovery.pub is missing: run `make keys`")
endif()

idf_build_get_property(image ESPDNS_IMAGE)
idf_build_get_property(fallback ESPDNS_FALLBACK)
idf_build_get_property(fallback_json ESPDNS_FALLBACK_JSON)
# Wi-Fi only on chips that have it; the P4 is wired only. PSRAM only on chips that have it.
idf_build_get_property(target IDF_TARGET)
set(wifi "")
if(target MATCHES "^esp32(|s3|c3|c6)$")
    set(wifi esp_wifi)
endif()
set(psram "")
if(target MATCHES "^esp32(|s3|p4)$")
    set(psram esp_psram)
endif()
# A transitional image carries its catalog board as the fallback definition.
set(embed "${RELEASE_PUB}" "${RECOVERY_PUB}")
if(fallback_json)
    configure_file("${fallback_json}" "${CMAKE_BINARY_DIR}/fallback_board.json" COPYONLY)
    list(APPEND embed "${CMAKE_BINARY_DIR}/fallback_board.json")
endif()

set(srcs "main.c" "boot.c" "board.c" "board_def.c" "net.c" "improv.c" "server.c" "xfr.c" "forward.c" "registry.c" "ota.c" "release.c"
         "dns_wire.c" "zone.c" "axfr.c" "answer.c" "cache.c" "flight.c" "fwdq.c" "upq.c" "blocklist.c" "block.c" "blocking.c"
         "hzone.c" "hosted.c"
         "sd.c" "health.c" "health_node.c" "led.c" "cfg.c" "settings.c" "clock.c" "reboot.c"
         "svc.c" "services.c" "memplan.c" "share.c" "sup.c" "supervisor.c" "cpuplan.c" "power.c"
         "qlog.c" "stats.c" "metrics.c" "querylog.c" "metrics_node.c" "httpguard.c" "jsonw.c")
set(incs ".")
# Bench build (`make bench-ota`): POST /bench runs the blocklist benchmark; never confirms itself.
if(DNS2_BENCH_BLOCKLIST)
    list(APPEND srcs "bench_http.c" "${CMAKE_CURRENT_LIST_DIR}/../tests/bench_blocklist.c")
    list(APPEND incs "${CMAKE_CURRENT_LIST_DIR}/../tests")
endif()

idf_component_register(SRCS ${srcs}
                       INCLUDE_DIRS ${incs}
                       EMBED_FILES ${embed}
                       PRIV_REQUIRES esp_eth esp_netif esp_timer esp_event nvs_flash fatfs sdmmc
                                     esp_driver_sdmmc esp_driver_sdspi esp_driver_spi esp_driver_gpio
                                     esp_driver_usb_serial_jtag esp_driver_rmt ${wifi} ${psram} pthread lwip esp_http_server app_update
                                     esp_app_format mbedtls esp_hw_support esp_pm esp_partition json)

target_compile_definitions(${COMPONENT_LIB} PRIVATE ESPDNS_IMAGE="${image}")
if(fallback)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ESPDNS_FALLBACK="${fallback}")
endif()

# STATIC_IP=a.b.c.d builds in the address a node starts on (config.h), for a transitional
# image of a node in service, with STATIC_NETMASK and STATIC_GATEWAY (required with it);
# the board definition and a node config override it. Without it there is none. There is
# no DHCP setting here: only a board definition or node config asks for DHCP.
if(STATIC_IP STREQUAL "dhcp")
    message(FATAL_ERROR "STATIC_IP=dhcp: a node asks DHCP only when its board definition or node config says so")
elseif(STATIC_IP)
    if(NOT STATIC_NETMASK OR NOT STATIC_GATEWAY)
        message(FATAL_ERROR "STATIC_IP=${STATIC_IP}: give STATIC_NETMASK= and STATIC_GATEWAY= with it")
    endif()
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_STATIC_IP="${STATIC_IP}"
                               DNS2_NETMASK="${STATIC_NETMASK}" DNS2_GATEWAY="${STATIC_GATEWAY}")
endif()

# SITE_DEFAULTS=<file.h>: a deployment's own firmware defaults, included by config.h
# (firmware/site-defaults.h.example). Empty: the project's.
if(SITE_DEFAULTS)
    if(NOT EXISTS "${SITE_DEFAULTS}")
        message(FATAL_ERROR "SITE_DEFAULTS: no such file: ${SITE_DEFAULTS}")
    endif()
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_SITE_DEFAULTS="${SITE_DEFAULTS}")
endif()

# Test hook: `idf.py -B build-rollback -DDNS2_TEST_FAIL_HEALTH=1 build` makes a build that
# never passes its post-update health check, to prove rollback works.
if(DNS2_BENCH_BLOCKLIST)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_BENCH_BLOCKLIST=1 BENCH_NO_MAIN=1)
endif()
if(DNS2_TEST_FAIL_HEALTH)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_TEST_FAIL_HEALTH=1)
endif()
# Supervisor test hooks (sup.h), for a node out of service:
#   -DDNS2_TEST_START_FAILS=n  blocking's start fails its first n times: restarted with backoff,
#                              "service restarting", then "service failed" from the third
#   -DDNS2_TEST_STALL_S=s      the UDP receive task hangs s seconds after each boot: the
#                              listeners stall, the node reboots 3 times, then stays in fault
if(DNS2_TEST_START_FAILS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_TEST_START_FAILS=${DNS2_TEST_START_FAILS})
endif()
if(DNS2_TEST_STALL_S)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DNS2_TEST_STALL_S=${DNS2_TEST_STALL_S})
endif()
