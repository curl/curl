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

# Get BUNDLE, FIRSTFILES, UTILS, CURLX_CFILES, TESTFILES, STUB_GSS variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

if(LIB_SELECTED STREQUAL LIB_STATIC)
  set(CURLX_CFILES "")  # Already exported from the libcurl static build. Skip them.
endif()

add_custom_command(OUTPUT "lib1521.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl" < "${PROJECT_SOURCE_DIR}/include/curl/curl.h" "lib1521.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${PROJECT_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)

list(APPEND TESTFILES "lib1521.c")

add_custom_command(OUTPUT "${BUNDLE}.c"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl"
    --include ${UTILS} ${CURLX_CFILES} --test ${TESTFILES} > "${BUNDLE}.c"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    ${FIRSTFILES} ${UTILS} ${CURLX_CFILES} ${TESTFILES}
  VERBATIM)

add_executable(${BUNDLE} EXCLUDE_FROM_ALL "${BUNDLE}.c")
add_dependencies(testdeps ${BUNDLE})
target_link_libraries(${BUNDLE} ${LIB_SELECTED} ${CURL_LIBS})
target_include_directories(${BUNDLE} PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${CMAKE_CURRENT_SOURCE_DIR}"          # for the generated bundle source to find included test sources
  "${PROJECT_SOURCE_DIR}/tests/unit"     # for "curlcheck.h"
)
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_NO_OLDIES" "CURL_DISABLE_DEPRECATION")
set_target_properties(${BUNDLE} PROPERTIES OUTPUT_NAME "${BUNDLE}" PROJECT_LABEL "Test ${BUNDLE}" UNITY_BUILD OFF C_CLANG_TIDY "")

curl_clang_tidy_tests(${BUNDLE} ${FIRSTFILES} ${UTILS} ${TESTFILES})

if(HAVE_GSSAPI AND UNIX)
  add_library(stubgss SHARED EXCLUDE_FROM_ALL ${STUB_GSS})
  set_target_properties(stubgss PROPERTIES UNITY_BUILD OFF)
  add_dependencies(testdeps stubgss)
endif()
