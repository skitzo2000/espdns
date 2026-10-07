cmake_minimum_required(VERSION 3.19)

# What to build (docs/design.md, Boards and images):
#   IMAGE  the chip image, images/<image>/sdkconfig.defaults (esp32s3-octal, esp32p4-rev1, ...)
#   BOARD  optional: a catalog board (BOARDS_DIR/<board>.json) built in as the fallback, for a
#          node whose flash has no `board` partition yet. IMAGE defaults to the board's image.
set(IMAGE "" CACHE STRING "Chip image to build (images/<image>)")
set(BOARD "" CACHE STRING "Catalog board to build in as the fallback (transitional images)")
set(BOARDS_DIR "${CMAKE_CURRENT_LIST_DIR}/../boards" CACHE PATH "Board catalog")

set(fallback_json "")
if(BOARD)
    set(fallback_json "${BOARDS_DIR}/${BOARD}.json")
    if(NOT EXISTS "${fallback_json}")
        message(FATAL_ERROR "unknown board ${BOARD}: no ${fallback_json}")
    endif()
    file(READ "${fallback_json}" board_def)
    string(JSON board_image GET "${board_def}" image)
    if(NOT IMAGE)
        set(IMAGE "${board_image}")
    elseif(NOT IMAGE STREQUAL board_image)
        message(FATAL_ERROR "board ${BOARD} runs image ${board_image}, not ${IMAGE}")
    endif()
endif()
if(NOT IMAGE OR NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/images/${IMAGE}/sdkconfig.defaults")
    message(FATAL_ERROR "set IMAGE to one of images/<image> (got '${IMAGE}')")
endif()

set(SDKCONFIG_DEFAULTS "sdkconfig.defaults;images/${IMAGE}/sdkconfig.defaults")
# For experiments: one more defaults file on top, e.g. -DEXTRA_SDKCONFIG=build/wpa2-only.defaults
if(EXTRA_SDKCONFIG)
    list(APPEND SDKCONFIG_DEFAULTS "${EXTRA_SDKCONFIG}")
endif()

# The version: the repository's VERSION (version.cmake), as the app descriptor's version (what
# /status, the image header and the controller say), never `git describe`. The build
# containers mount it at /VERSION, this directory's parent (firmware/Makefile). A change to it
# configures the build again.
include("${CMAKE_CURRENT_LIST_DIR}/version.cmake")
espdns_version("${CMAKE_CURRENT_LIST_DIR}/../VERSION" PROJECT_VER)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/../VERSION")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(ESPDNS_IMAGE "${IMAGE}")
idf_build_set_property(ESPDNS_FALLBACK "${BOARD}")
idf_build_set_property(ESPDNS_FALLBACK_JSON "${fallback_json}")
# The component lock, committed so every checkout builds the same components: one per chip
# target, because the component manager records the target in it and, for any other, solves
# again over the network and rewrites it. A build only reads it (offline, the source
# read-only); `make components` writes it (firmware/README.md, Builds and the release key).
idf_build_set_property(DEPENDENCIES_LOCK "${CMAKE_CURRENT_LIST_DIR}/dependencies.lock.${IDF_TARGET}")
project(dns2)
