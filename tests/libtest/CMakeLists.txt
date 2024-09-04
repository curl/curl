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

# Get 'noinst_PROGRAMS', '*_SOURCES', TESTUTIL, TSTTRACE, WARNLESS, MULTIBYTE, TIMEDIFF, THREADS variables
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

set_source_files_properties("../../lib/curl_multibyte.c" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)

add_custom_command(
  OUTPUT "lib1521.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl" < "${CURL_SOURCE_DIR}/include/curl/curl.h" > "lib1521.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${CURL_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)

if(CURL_TEST_USE_BUNDLES)
  unset(_allsources)
  foreach(_target IN LISTS noinst_PROGRAMS)
    if(DEFINED ${_target}_SOURCES)
      list(APPEND _allsources ${${_target}_SOURCES})
    else()
      list(APPEND _allsources ${nodist_${_target}_SOURCES})
    endif()
  endforeach()
  list(REMOVE_DUPLICATES _allsources)

  set(_extrasources ${TESTUTIL} ${TSTTRACE})
  if(LIB_SELECTED STREQUAL LIB_SHARED)
    # These are part of the libcurl static lib. Add them here when linking shared.
    list(APPEND _extrasources ${WARNLESS} ${MULTIBYTE} ${TIMEDIFF} ${THREADS})
  endif()

  add_custom_command(
    OUTPUT "libtests.c"
    COMMAND ${PERL_EXECUTABLE} "${CURL_SOURCE_DIR}/tests/mk-bundle.pl" "${CMAKE_CURRENT_SOURCE_DIR}" ${_extrasources} > "libtests.c"
    DEPENDS
      "${CURL_SOURCE_DIR}/tests/mk-bundle.pl"
      "${CMAKE_CURRENT_SOURCE_DIR}/Makefile.inc" ${_allsources}
    VERBATIM)

  set(noinst_PROGRAMS "libtests")
  set(libtests_SOURCES "libtests.c")
endif()

foreach(_target IN LISTS noinst_PROGRAMS)
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
    "${CURL_BINARY_DIR}/lib"            # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"            # for "curl_setup.h"
    "${CURL_SOURCE_DIR}/tests/libtest"  # to be able to build generated tests
  )
  if(CURL_TEST_USE_BUNDLES)
    set_target_properties(${_target_name} PROPERTIES UNITY_BUILD OFF)
  else()
    set_target_properties(${_target_name} PROPERTIES COMPILE_DEFINITIONS ${_upper_target})
  endif()
  set_target_properties(${_target_name} PROPERTIES
    OUTPUT_NAME "${_target}"
    PROJECT_LABEL "Test libtest ${_target}")
endforeach()
