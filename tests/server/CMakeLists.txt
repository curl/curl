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
set(TARGET_LABEL_PREFIX "Test server ")

if(MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4306")
endif()

function(setup_executable test_name)  # ARGN are the files in the test
  add_executable(${test_name} EXCLUDE_FROM_ALL ${ARGN})
  add_dependencies(testdeps ${test_name})

  include_directories(
    "${CURL_BINARY_DIR}/lib"  # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"  # for "curl_setup.h"
    "${CURL_SOURCE_DIR}/src"  # for "tool_xattr.h" in disabled_SOURCES
  )
  if(USE_ARES)
    include_directories(${CARES_INCLUDE_DIR})
  endif()

  target_link_libraries(${test_name} ${CURL_LIBS})

  # Test servers simply are standalone programs that do not use libcurl
  # library.  For convenience and to ease portability of these servers,
  # some source code files from the libcurl subdirectory are also used
  # to build the servers.  In order to achieve proper linkage of these
  # files on Windows targets it is necessary to build the test servers
  # with CURL_STATICLIB defined, independently of how libcurl is built.
  set_target_properties(${test_name} PROPERTIES
    COMPILE_DEFINITIONS CURL_STATICLIB)
  set_target_properties(${test_name} PROPERTIES
    PROJECT_LABEL "${TARGET_LABEL_PREFIX}${test_name}")
endfunction()

# Get 'noinst_PROGRAMS', '<target>_SOURCES' variables
transform_makefile_inc("Makefile.inc"
  "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

foreach(_executable_name IN LISTS noinst_PROGRAMS)
  setup_executable(${_executable_name} ${${_executable_name}_SOURCES})
endforeach()
