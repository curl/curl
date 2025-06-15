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

# Get BUNDLE, BUNDLE_SRC, FIRSTFILES, UTILS, MEMDEBUG, CURLX_SRCS, TESTFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set(_bundle_exclude "")
if(ENABLE_SERVER_DEBUG AND ENABLE_CURLDEBUG)
  list(APPEND _bundle_exclude ${MEMDEBUG})
endif()

add_custom_command(
  OUTPUT "${BUNDLE_SRC}"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl"
    --include ${UTILS} ${MEMDEBUG} ${CURLX_SRCS} --test ${TESTFILES} --exclude ${_bundle_exclude}
    ${CURL_MK_UNITY_OPTION} --srcdir "${CMAKE_CURRENT_SOURCE_DIR}" > "${BUNDLE_SRC}"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    ${FIRSTFILES} ${UTILS} ${MEMDEBUG} ${CURLX_SRCS} ${TESTFILES}
  VERBATIM)

add_executable(servers EXCLUDE_FROM_ALL "${BUNDLE_SRC}" ${_bundle_exclude})
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
set_property(TARGET servers APPEND PROPERTY COMPILE_DEFINITIONS "WITHOUT_LIBCURL" "CURL_NO_OLDIES")
# Test servers simply are standalone programs that do not use libcurl
# library.  For convenience and to ease portability of these servers,
# some source code files from the libcurl subdirectory are also used
# to build the servers.  In order to achieve proper linkage of these
# files on Windows targets it is necessary to build the test servers
# with CURL_STATICLIB defined, independently of how libcurl is built.
if(WIN32)
  set_property(TARGET servers APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
endif()
set_target_properties(servers PROPERTIES OUTPUT_NAME "${BUNDLE}" PROJECT_LABEL "Test ${BUNDLE}" UNITY_BUILD OFF)
