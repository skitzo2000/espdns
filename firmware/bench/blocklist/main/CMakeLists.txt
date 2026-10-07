# The list file and queries come from controller/cmd/blockbench -write (data/, not committed).
set(FW ${CMAKE_CURRENT_LIST_DIR}/../../..)
idf_component_register(SRCS "app.c" "${FW}/tests/bench_blocklist.c" "${FW}/main/blocklist.c" "${FW}/main/dns_wire.c"
                       INCLUDE_DIRS "${FW}/main" "${FW}/tests"
                       EMBED_FILES "${CMAKE_CURRENT_LIST_DIR}/../data/list.bin" "${CMAKE_CURRENT_LIST_DIR}/../data/q.txt")
target_compile_definitions(${COMPONENT_LIB} PRIVATE BENCH_NO_MAIN)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
