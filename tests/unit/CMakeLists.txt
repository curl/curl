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

# Get 'FIRSTFILES', 'UTILS', 'TESTFILES' variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(
  OUTPUT "unit_bundle.c"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" --test ${TESTFILES}
    ${CURL_MK_UNITY_OPTION} --srcdir "${CMAKE_CURRENT_SOURCE_DIR}" > "unit_bundle.c"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" ${FIRSTFILES} ${TESTFILES}
    "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
  VERBATIM)

add_executable(units EXCLUDE_FROM_ALL ${UTILS} "unit_bundle.c")
add_dependencies(testdeps units)
target_link_libraries(units curltool curlu)
target_include_directories(units PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/tests/unit"
)
set_property(TARGET units APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}" "CURL_NO_OLDIES" "CURL_DISABLE_DEPRECATION")
set_property(TARGET units APPEND PROPERTY COMPILE_DEFINITIONS "BUILDING_LIBCURL")  # unit tests are small pretend-libcurl-programs
set_target_properties(units PROPERTIES
  OUTPUT_NAME "units"
  PROJECT_LABEL "Test units")
