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

# Get 'UNITPROGS', 'UNITFILES' variables
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

include_directories(
  "${CURL_BINARY_DIR}/lib"            # for "curl_config.h"
  "${CURL_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${CURL_SOURCE_DIR}/src"
  "${CURL_SOURCE_DIR}/tests/libtest"
)

foreach(_test_name IN LISTS UNITPROGS)
  add_executable(${_test_name} EXCLUDE_FROM_ALL "${_test_name}.c" ${UNITFILES})
  add_dependencies(testdeps ${_test_name})
  target_link_libraries(${_test_name} curltool curlu)
  set_target_properties(${_test_name} PROPERTIES
    PROJECT_LABEL "Test unit ${_test_name}")
endforeach()
