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

# Get BUNDLE, FIRST_C, TESTS_C variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT "${BUNDLE}.c"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl"
    --test ${TESTS_C} > "${BUNDLE}.c"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    ${FIRST_C} ${TESTS_C}
  VERBATIM)

add_executable(${BUNDLE} EXCLUDE_FROM_ALL "${BUNDLE}.c")
add_dependencies(testdeps ${BUNDLE})
target_link_libraries(${BUNDLE} curltool ${LIB_SELECTED})
target_include_directories(${BUNDLE} PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h", curlx
  "${PROJECT_SOURCE_DIR}/src"            # for tool headers
  "${PROJECT_SOURCE_DIR}/tests/libtest"  # for "first.h"
  "${PROJECT_SOURCE_DIR}/tests/unit"     # for "curlcheck.h"
  "${CMAKE_CURRENT_SOURCE_DIR}"          # for the generated bundle source to find included test sources
)
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_NO_OLDIES" "CURL_DISABLE_DEPRECATION")
set_target_properties(${BUNDLE} PROPERTIES OUTPUT_NAME "${BUNDLE}" PROJECT_LABEL "Test ${BUNDLE}" UNITY_BUILD OFF C_CLANG_TIDY "")

curl_clang_tidy_tests(${BUNDLE} ${FIRST_C} ${TESTS_C})
