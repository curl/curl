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
function(setup_executable _test_name)  # ARGN are the files in the test
  add_executable(${_test_name} EXCLUDE_FROM_ALL ${ARGN})
  add_dependencies(testdeps ${_test_name})

  include_directories(
    "${CURL_BINARY_DIR}/lib"  # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"  # for "curl_setup.h"
    "${CURL_SOURCE_DIR}/src"  # for "tool_xattr.h" in disabled_SOURCES
  )

  target_link_libraries(${_test_name} ${CURL_LIBS})

  # Test servers simply are standalone programs that do not use libcurl
  # library.  For convenience and to ease portability of these servers,
  # some source code files from the libcurl subdirectory are also used
  # to build the servers.  In order to achieve proper linkage of these
  # files on Windows targets it is necessary to build the test servers
  # with CURL_STATICLIB defined, independently of how libcurl is built.
  set_target_properties(${_test_name} PROPERTIES
    COMPILE_DEFINITIONS "CURL_STATICLIB"
    PROJECT_LABEL "Test server ${_test_name}")
endfunction()

# Get 'noinst_PROGRAMS', '<target>_SOURCES' variables
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

foreach(_executable_name IN LISTS noinst_PROGRAMS)
  setup_executable(${_executable_name} ${${_executable_name}_SOURCES})
endforeach()
