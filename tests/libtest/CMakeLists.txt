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

# Get 'LIBTESTPROGS', '*_SOURCES', 'TESTUTIL', 'TSTTRACE', 'WARNLESS', 'MULTIBYTE', 'TIMEDIFF', 'THREADS', 'FIRSTFILES' variables
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set_source_files_properties("../../lib/curl_multibyte.c" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

add_custom_command(
  OUTPUT "lib1521.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl" < "${PROJECT_SOURCE_DIR}/include/curl/curl.h" "lib1521.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${PROJECT_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)

if(CURL_TEST_BUNDLES)
  add_custom_command(
    OUTPUT "libtest_bundle.c"
    COMMAND ${PERL_EXECUTABLE} "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" "${CMAKE_CURRENT_SOURCE_DIR}" > "libtest_bundle.c"
    DEPENDS
      "${PROJECT_SOURCE_DIR}/tests/mk-bundle.pl" ${FIRSTFILES} "lib1521.c"
      "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc"
    VERBATIM)

  set(LIBTESTPROGS "libtests")
  set(libtests_SOURCES "libtest_bundle.c")
  list(APPEND libtests_SOURCES ${TESTUTIL} ${TSTTRACE})
  if(LIB_SELECTED STREQUAL LIB_SHARED)
    # These are part of the libcurl static lib. Add them here when linking shared.
    list(APPEND libtests_SOURCES ${WARNLESS} ${MULTIBYTE} ${TIMEDIFF} ${THREADS})
  endif()
endif()

foreach(_target IN LISTS LIBTESTPROGS)
  if(DEFINED ${_target}_SOURCES)
    set(_sources ${${_target}_SOURCES})
  else()
    set(_sources ${nodist_${_target}_SOURCES})
  endif()

  if(LIB_SELECTED STREQUAL LIB_STATIC)
    # These are part of the libcurl static lib. Do not compile/link them again.
    list(REMOVE_ITEM _sources ${WARNLESS} ${MULTIBYTE} ${TIMEDIFF} ${THREADS})
  endif()

  string(TOUPPER ${_target} _upper_target)
  set(_target_name "${_target}")
  add_executable(${_target_name} EXCLUDE_FROM_ALL ${_sources})
  add_dependencies(testdeps ${_target_name})
  target_link_libraries(${_target_name} ${LIB_SELECTED} ${CURL_LIBS})
  target_include_directories(${_target_name} PRIVATE
    "${PROJECT_BINARY_DIR}/lib"            # for "curl_config.h"
    "${PROJECT_SOURCE_DIR}/lib"            # for "curl_setup.h"
    "${PROJECT_SOURCE_DIR}/tests/libtest"  # to be able to build generated tests
  )
  if(NOT CURL_TEST_BUNDLES)
    set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS ${_upper_target})
  endif()
  set_property(TARGET ${_target_name} APPEND PROPERTY COMPILE_DEFINITIONS "CURL_NO_GETADDRINFO_OVERRIDE")
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}"
    PROJECT_LABEL "Test libtest ${_target}")
endforeach()
