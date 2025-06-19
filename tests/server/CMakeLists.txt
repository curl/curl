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

# Get BUNDLE, BUNDLE_SRC, FIRSTFILES, UTILS, CURLX_CFILES, TESTFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT "${BUNDLE_SRC}"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" --include ${UTILS} ${CURLX_CFILES} --test ${TESTFILES}
    ${CURL_MK_UNITY_OPTION} --srcdir "${CMAKE_CURRENT_SOURCE_DIR}" > "${BUNDLE_SRC}"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    ${FIRSTFILES} ${UTILS} ${CURLX_CFILES} ${TESTFILES}
  VERBATIM)

add_executable(${BUNDLE} EXCLUDE_FROM_ALL "${BUNDLE_SRC}")
add_dependencies(testdeps ${BUNDLE})
target_link_libraries(${BUNDLE} ${CURL_LIBS})
target_include_directories(${BUNDLE} PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${CMAKE_CURRENT_SOURCE_DIR}"          # for the generated bundle source to find included test sources
)
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "WITHOUT_LIBCURL")
set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_NO_OLDIES")
# Test servers simply are standalone programs that do not use libcurl
# library.  For convenience and to ease portability of these servers,
# some source code files from the libcurl subdirectory are also used
# to build the servers.  In order to achieve proper linkage of these
# files on Windows targets it is necessary to build the test servers
# with CURL_STATICLIB defined, independently of how libcurl is built.
if(WIN32)
  set_property(TARGET ${BUNDLE} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
endif()
set_target_properties(${BUNDLE} PROPERTIES OUTPUT_NAME "${BUNDLE}" PROJECT_LABEL "Test ${BUNDLE}" UNITY_BUILD OFF)
