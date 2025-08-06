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

add_custom_target(curl-examples)

# Get check_PROGRAMS variable
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set(_all "all")
foreach(_target IN LISTS check_PROGRAMS _all)
  set(_target_name "curl-example-${_target}")
  if(_target STREQUAL "all")
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
      set(_example_c "${check_PROGRAMS}")
      list(TRANSFORM _example_c APPEND ".c")
      add_library(${_target_name} OBJECT EXCLUDE_FROM_ALL ${_example_c})
      message(STATUS "|${_example_c}|")
    endif()
  else()
    set(_onetest ${_target_name})  # ends with a single, existing test for curl-examples-build target
    add_executable(${_target_name} EXCLUDE_FROM_ALL "${_target}.c")
    add_dependencies(curl-examples ${_target_name})
  endif()
  target_link_libraries(${_target_name} ${LIB_SELECTED} ${CURL_NETWORK_AND_TIME_LIBS})
  target_compile_definitions(${_target_name} PRIVATE "CURL_NO_OLDIES"
    "$<$<BOOL:${WIN32}>:WIN32_LEAN_AND_MEAN>" "$<$<BOOL:${MSVC}>:_CRT_SECURE_NO_DEPRECATE>")
  set_target_properties(${_target_name} PROPERTIES OUTPUT_NAME "${_target}" PROJECT_LABEL "Example ${_target}" UNITY_BUILD OFF)
endforeach()

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.12)
  # Special target to compile all tests quickly and build a single test to probe linkage
  add_custom_target(curl-examples-build)
  add_dependencies(curl-examples-build curl-example-all "${_onetest}")
endif()
