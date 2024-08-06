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

# Get 'check_PROGRAMS' variable
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

foreach(_client IN LISTS check_PROGRAMS)
  set(_client_target "curl-test-client-${_client}")
  add_executable(${_client_target} "${_client}.c")
  add_dependencies(testdeps ${_client_target})
  target_include_directories(${_client_target} PRIVATE
    "${CURL_BINARY_DIR}/lib"  # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"  # for "curl_setup.h"
  )
  target_link_libraries(${_client_target} ${LIB_SELECTED} ${CURL_LIBS})
  target_compile_definitions(${_client_target} PRIVATE "CURL_NO_OLDIES")
  if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
    set_property(TARGET ${_client_target} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  set_target_properties(${_client_target} PROPERTIES OUTPUT_NAME "${_client}" UNITY_BUILD OFF)
endforeach()
