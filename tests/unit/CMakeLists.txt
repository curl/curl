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

# TODO build a special libcurlu library for unittests.
#return()

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

include_directories(
  ${CURL_SOURCE_DIR}/lib          # To be able to reach "curl_setup_once.h"
  ${CURL_SOURCE_DIR}/tests/libtest
  ${CURL_SOURCE_DIR}/src
  ${CURL_BINARY_DIR}/lib          # To be able to reach "curl_config.h"
  ${CURL_BINARY_DIR}/include      # To be able to reach "curl/curl.h"
)

foreach(_testfile ${UNITPROGS})
  add_executable(${_testfile} EXCLUDE_FROM_ALL ${_testfile}.c ${UNITFILES})
  add_dependencies(testdeps ${_testfile})
  target_link_libraries(${_testfile} libcurl ${CURL_LIBS})
  set_target_properties(${_testfile}
      PROPERTIES COMPILE_DEFINITIONS "UNITTESTS")
endforeach()
