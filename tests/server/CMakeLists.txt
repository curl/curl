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

# Get 'TESTS', 'MEMDEBUG', 'UTILS', 'FIRSTFILES'
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

if(ENABLE_SERVER_DEBUG AND ENABLE_CURLDEBUG)
  set_source_files_properties("../../lib/memdebug.c" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
endif()

add_custom_command(
  OUTPUT "server_bundle.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-bundle.pl" ${TESTS} > "server_bundle.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-bundle.pl" ${FIRSTFILES} ${TESTS}
    "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
  VERBATIM)

add_executable(servers EXCLUDE_FROM_ALL ${MEMDEBUG} ${UTILS} "server_bundle.c")
add_dependencies(testdeps servers)
target_include_directories(servers PRIVATE
  "${PROJECT_BINARY_DIR}/lib"           # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"           # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"     # for curlx
  "${PROJECT_SOURCE_DIR}/src"           # for "tool_binmode.h", "tool_xattr.h"
  "${PROJECT_SOURCE_DIR}/tests/server"  # for "first.h"
)
target_link_libraries(servers ${CURL_LIBS})
if(ENABLE_SERVER_DEBUG)
  set_property(TARGET servers APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")
endif()
set_property(TARGET servers APPEND PROPERTY COMPILE_DEFINITIONS "WITHOUT_LIBCURL")
# Test servers simply are standalone programs that do not use libcurl
# library.  For convenience and to ease portability of these servers,
# some source code files from the libcurl subdirectory are also used
# to build the servers.  In order to achieve proper linkage of these
# files on Windows targets it is necessary to build the test servers
# with CURL_STATICLIB defined, independently of how libcurl is built.
if(WIN32)
  set_property(TARGET servers APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
endif()
set_target_properties(servers PROPERTIES
  OUTPUT_NAME "servers"
  PROJECT_LABEL "Test servers")
