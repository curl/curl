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

foreach(_target IN LISTS check_PROGRAMS)
  set(_target_name "curlt-client-${_target}")
  add_executable(${_target_name} EXCLUDE_FROM_ALL "${_target}.c")
  add_dependencies(testdeps ${_target_name})
  target_include_directories(${_target_name} PRIVATE
    "${CURL_BINARY_DIR}/lib"  # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"  # for "curl_setup.h"
  )
  target_link_libraries(${_target_name} ${LIB_SELECTED} ${CURL_LIBS})
  target_compile_definitions(${_target_name} PRIVATE "CURL_NO_OLDIES")
  if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
    set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
  endif()
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}" UNITY_BUILD OFF
    PROJECT_LABEL "Test client ${_target}")
endforeach()
