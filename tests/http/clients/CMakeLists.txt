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

foreach(_test_name IN LISTS check_PROGRAMS)
  set(_test_target "curl-test-client-${_test_name}")
  add_executable(${_test_target} "${_test_name}.c")
  add_dependencies(testdeps ${_test_target})
  target_include_directories(${_test_target} PRIVATE
    "${CURL_BINARY_DIR}/lib"  # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"  # for "curl_setup.h"
  )
  target_link_libraries(${_test_target} ${LIB_SELECTED} ${CURL_LIBS})
  target_compile_definitions(${_test_target} PRIVATE "CURL_NO_OLDIES")
  if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
    set_property(TARGET ${_test_target} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  set_target_properties(${_test_target} PROPERTIES
    OUTPUT_NAME "${_test_name}" UNITY_BUILD OFF
    PROJECT_LABEL "Test client ${_test_target}")
endforeach()
