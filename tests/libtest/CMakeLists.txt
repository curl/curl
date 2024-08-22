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
function(setup_test _target)  # ARGN are the files in the test

  if(LIB_SELECTED STREQUAL LIB_STATIC)
    # These are part of the libcurl static lib. Do not compile/link them again.
    list(REMOVE_ITEM ARGN ${WARNLESS} ${MULTIBYTE} ${TIMEDIFF})
  endif()

  add_executable(${_target} EXCLUDE_FROM_ALL ${ARGN})
  add_dependencies(testdeps ${_target})
  string(TOUPPER ${_target} _upper_target)

  include_directories(
    "${CURL_BINARY_DIR}/lib"            # for "curl_config.h"
    "${CURL_SOURCE_DIR}/lib"            # for "curl_setup.h"
    "${CURL_SOURCE_DIR}/tests/libtest"  # to be able to build generated tests
  )

  target_link_libraries(${_target} ${LIB_SELECTED} ${CURL_LIBS})

  set_target_properties(${_target} PROPERTIES
    COMPILE_DEFINITIONS ${_upper_target}
    PROJECT_LABEL "Test ${_target}")
endfunction()

# Get 'noinst_PROGRAMS', '*_SOURCES', WARNLESS, MULTIBYTE, TIMEDIFF variables
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

foreach(_target IN LISTS noinst_PROGRAMS)
  if(DEFINED ${_target}_SOURCES)
    setup_test(${_target} ${${_target}_SOURCES})
  else()
    setup_test(${_target} ${nodist_${_target}_SOURCES})
  endif()
endforeach()

# Allows for hostname override to make tests machine independent.
# TODO: this cmake build assumes a shared build, detect static linking here!
if(NOT WIN32)
  add_library(hostname MODULE EXCLUDE_FROM_ALL "sethostname.c")
  add_dependencies(testdeps hostname)
  # Output to .libs for compatibility with autotools, the test data expects a
  # library at (tests)/libtest/.libs/libhostname.so
  set_target_properties(hostname PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/.libs")
  if(CURL_HIDES_PRIVATE_SYMBOLS)
    set_property(TARGET hostname APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
    set_property(TARGET hostname APPEND PROPERTY COMPILE_FLAGS ${CURL_CFLAG_SYMBOLS_HIDE})
  endif()
endif()

add_custom_command(
  OUTPUT "lib1521.c"
  COMMAND ${PERL_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl" < "${CURL_SOURCE_DIR}/include/curl/curl.h" > "lib1521.c"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${CURL_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)
