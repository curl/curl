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

# Get 'TESTS', 'FIRSTFILES' variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(
  OUTPUT "tool_bundle.c"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${TESTS} > "tool_bundle.c"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${FIRSTFILES} ${TESTS}
    "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
  VERBATIM)

add_executable(tunits EXCLUDE_FROM_ALL "tool_bundle.c")
add_dependencies(testdeps tunits)
target_link_libraries(tunits curltool curlu)
target_include_directories(tunits PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${PROJECT_SOURCE_DIR}/src"
  "${PROJECT_SOURCE_DIR}/tests/libtest"
  "${PROJECT_SOURCE_DIR}/tests/unit"     # for curlcheck.h
  "${PROJECT_SOURCE_DIR}/tests/tunit"
)
set_property(TARGET tunits APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")
set_target_properties(tunits PROPERTIES
  OUTPUT_NAME "tunits"
  PROJECT_LABEL "Test tunits")
