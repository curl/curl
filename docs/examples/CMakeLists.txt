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

transform_makefile_inc("Makefile.inc"
  "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)
# Get 'check_PROGRAMS' variable

foreach(example IN LISTS check_PROGRAMS)
  set(example_target "curl-example-${example}")
  add_executable(${example_target} "${example}.c")
  target_include_directories(${example_target} PRIVATE
    "${CURL_SOURCE_DIR}/lib"      # for "curl_setup_once.h"
    "${CURL_BINARY_DIR}/lib"      # for "curl_config.h"
    "${CURL_BINARY_DIR}/include"  # for "curl/curl.h"
  )
  target_link_libraries(${example_target} ${LIB_SELECTED} ${CURL_LIBS})
  target_compile_definitions(${example_target} PRIVATE "CURL_NO_OLDIES")
  if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
    set_property(TARGET ${example_target} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  set_target_properties(${example_target} PROPERTIES OUTPUT_NAME "${example}" UNITY_BUILD OFF)
endforeach()
