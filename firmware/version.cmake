# The version (docs/plan.md, Phase F, "Versions"): the repository's VERSION, the one place it
# is set. espdns_version(<file> <var>) reads it into <var>, MAJOR.MINOR.PATCH, or stops the
# build saying what is wrong. CMakeLists.txt makes it the app descriptor's version.
#
# As a script, for the tests (tests/test_version.py): cmake -DVERSION_FILE=<file> -P version.cmake
# prints the version.
function(espdns_version file var)
    if(NOT EXISTS "${file}")
        message(FATAL_ERROR "no ${file}: the repository's VERSION names the version built")
    endif()
    file(READ "${file}" text)
    if(NOT text MATCHES "^((0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*))\n$")
        message(FATAL_ERROR "${file}: not one line MAJOR.MINOR.PATCH (whole numbers, no leading zeros)")
    endif()
    set(v "${CMAKE_MATCH_1}")
    # At most 9 digits each, as the controller (internal/version, MaxDigits) and
    # scripts/bump-version.sh take them; the longest fits the descriptor's 32 bytes
    if(v MATCHES "[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]")
        message(FATAL_ERROR "${file}: ${v}: a number of more than 9 digits")
    endif()
    set(${var} "${v}" PARENT_SCOPE)
endfunction()

if(CMAKE_SCRIPT_MODE_FILE STREQUAL CMAKE_CURRENT_LIST_FILE)
    espdns_version("${VERSION_FILE}" v)
    message("${v}")
endif()
