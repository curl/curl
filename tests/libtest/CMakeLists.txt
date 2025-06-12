#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################

# Get 'TESTS', 'TESTUTILS', 'UTILS', 'FIRSTFILES' variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(
  OUTPUT "lib1521.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl" < "${PROJECT_SOURCE_DIR}/include/curl/curl.h" "lib1521.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${PROJECT_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)

add_custom_command(
  OUTPUT "libtest_bundle.c"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${TESTS} "lib1521.c" > "libtest_bundle.c"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${FIRSTFILES} ${TESTS} "lib1521.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
  VERBATIM)

set(_sources "libtest_bundle.c" ${TESTUTILS})
if(LIB_SELECTED STREQUAL LIB_SHARED)
  list(APPEND _sources ${UTILS})  # These are part of the libcurl static lib. Add them here when linking shared.
endif()

add_executable(libtests EXCLUDE_FROM_ALL ${_sources})
add_dependencies(testdeps libtests)
target_link_libraries(libtests ${LIB_SELECTED} ${CURL_LIBS})
target_include_directories(libtests PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${PROJECT_SOURCE_DIR}/src"            # for "tool_binmode.h"
  "${PROJECT_SOURCE_DIR}/tests/libtest"  # to be able to build generated tests
  "${PROJECT_SOURCE_DIR}/tests/unit"     # for curlcheck.h
)
set_property(TARGET libtests APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")
set_target_properties(libtests PROPERTIES
  OUTPUT_NAME libtests
  PROJECT_LABEL "Test libtests")
