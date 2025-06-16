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
# Get BUNDLE, BUNDLE_SRC, CURLX_SRCS, FIRSTFILES, TESTFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set(_bundle_extra "")
if(LIB_SELECTED STREQUAL LIB_SHARED)
  list(APPEND _bundle_extra ${CURLX_SRCS})  # Not exported from the libcurl shared build. Build a copy.
endif()

add_custom_command(
  OUTPUT "${BUNDLE_SRC}"
  COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl"
    --include ${_bundle_extra} --test ${TESTFILES}
    ${CURL_MK_UNITY_OPTION} --srcdir "${CMAKE_CURRENT_SOURCE_DIR}" > "${BUNDLE_SRC}"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/mk-unity.pl" "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    ${FIRSTFILES} ${_bundle_extra} ${TESTFILES}
  VERBATIM)

add_executable(http-clients EXCLUDE_FROM_ALL "${BUNDLE_SRC}")
add_dependencies(testdeps http-clients)
target_include_directories(http-clients PRIVATE
  "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib/curlx"      # for curlx
  "${CMAKE_CURRENT_SOURCE_DIR}"          # for "first.h"
)
target_link_libraries(http-clients ${LIB_SELECTED} ${CURL_LIBS})
set_property(TARGET http-clients APPEND PROPERTY COMPILE_DEFINITIONS "CURL_NO_OLDIES"
  "$<$<BOOL:MSVC>:_CRT_SECURE_NO_DEPRECATE>")
if(LIB_SELECTED STREQUAL LIB_STATIC AND WIN32)
  set_property(TARGET http-clients APPEND PROPERTY COMPILE_DEFINITIONS "CURL_STATICLIB")
endif()
set_target_properties(http-clients PROPERTIES OUTPUT_NAME "${BUNDLE}" PROJECT_LABEL "Test ${BUNDLE}" UNITY_BUILD OFF)
