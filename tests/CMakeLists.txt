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
option(CURL_TEST_BUNDLES "Bundle libtest and unittest tests into single binaries" OFF)

find_program(TEST_NGHTTPX "nghttpx")
if(NOT TEST_NGHTTPX)
  set(TEST_NGHTTPX "nghttpx")
endif()
mark_as_advanced(TEST_NGHTTPX)
# Consumed variables: TEST_NGHTTPX
configure_file("config.in" "${CMAKE_CURRENT_BINARY_DIR}/config" @ONLY)

add_custom_target(testdeps)
add_subdirectory(http)
add_subdirectory(http/clients)
add_subdirectory(server)
add_subdirectory(libtest)
add_subdirectory(unit)
add_subdirectory(certs EXCLUDE_FROM_ALL)

function(add_runtests _targetname _test_flags)
  if(CURL_TEST_BUNDLES)
    set(_test_flags "${_test_flags} -bundle")
  endif()
  # Skip walking through dependent targets before running tests in CI.
  # This avoids: GNU Make doing a slow re-evaluation of all targets and
  # skipping them, MSBuild doing a re-evaluation, and actually rebuilding them.
  unset(_depends)
  if(NOT _targetname STREQUAL "test-ci")
    set(_depends "testdeps")
  endif()
  # Use a special '$TFLAGS' placeholder as last argument which will be
  # replaced by the contents of the environment variable in runtests.pl.
  # This is a workaround for CMake's limitation where commands executed by
  # 'make' or 'ninja' cannot portably reference environment variables.
  string(REPLACE " " ";" _test_flags_list "${_test_flags}")
  add_custom_target(${_targetname}
    COMMAND
      "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/runtests.pl"
      ${_test_flags_list}
      "\$TFLAGS"
    DEPENDS "${_depends}"
    VERBATIM USES_TERMINAL
  )
endfunction()

function(add_pytest _targetname _test_flags)
  unset(_depends)
  if(NOT _targetname STREQUAL "pytest-ci")
    set(_depends "test-http-clients")
  endif()
  string(REPLACE " " ";" _test_flags_list "${_test_flags}")
  add_custom_target(${_targetname}
    COMMAND pytest ${_test_flags_list} "${CMAKE_CURRENT_SOURCE_DIR}/http"
    DEPENDS "${_depends}"
    VERBATIM USES_TERMINAL
  )
endfunction()

# Create configurehelp.pm, used by tests needing to run the C preprocessor.
if(MSVC OR CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(CURL_CPP "\"${CMAKE_C_COMPILER}\" -E")
  if(APPLE AND CMAKE_OSX_SYSROOT)
    set(CURL_CPP "${CURL_CPP} -isysroot ${CMAKE_OSX_SYSROOT}")
  endif()
  # Add header directories, like autotools builds do.
  get_property(_include_dirs TARGET ${LIB_SELECTED} PROPERTY INCLUDE_DIRECTORIES)
  foreach(_include_dir IN LISTS _include_dirs)
    set(CURL_CPP "${CURL_CPP} -I${_include_dir}")
  endforeach()
else()
  set(CURL_CPP "cpp")
endif()
# Generate version script for the linker, for versioned symbols.
# Consumed variable:
#   CURL_CPP
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/configurehelp.pm.in"
  "${CMAKE_CURRENT_BINARY_DIR}/configurehelp.pm" @ONLY)

add_runtests(test-quiet     "-a -s")
add_runtests(test-am        "-a -am")
add_runtests(test-full      "-a -p -r")
# ~flaky means that it ignores results of tests using the flaky keyword
add_runtests(test-nonflaky  "-a -p ~flaky ~timing-dependent")
add_runtests(test-ci        "-a -p ~flaky ~timing-dependent -r -rm -j20")
add_runtests(test-torture   "-a -t -j20")
add_runtests(test-event     "-a -e")

add_pytest(curl-pytest      "")
add_pytest(curl-pytest-ci   "-v")
