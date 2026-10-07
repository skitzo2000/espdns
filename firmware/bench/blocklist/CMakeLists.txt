# On-board blocklist benchmark: tests/bench_blocklist.c with the node's own lookup code.
# Built and flashed with `make bench-board` in firmware/ (see the Makefile there).
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(blbench)
