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
set(CMAKE_UNITY_BUILD OFF)

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
    DEPENDS testdeps
    VERBATIM USES_TERMINAL
  )
endfunction()

# Create configurehelp.pm, used by tests needing to run the C preprocessor.
if(MSVC OR CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(_cpp_cmd "\"${CMAKE_C_COMPILER}\" -E")
  if(APPLE AND CMAKE_OSX_SYSROOT)
    set(_cpp_cmd "${_cpp_cmd} -isysroot ${CMAKE_OSX_SYSROOT}")
  endif()
  # Add header directories, like autotools builds do.
  get_property(_include_dirs TARGET ${LIB_SELECTED} PROPERTY INCLUDE_DIRECTORIES)
  foreach(_include_dir IN LISTS _include_dirs)
    set(_cpp_cmd "${_cpp_cmd} -I${_include_dir}")
  endforeach()
else()
  set(_cpp_cmd "cpp")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/configurehelp.pm" "# This is a generated file.  Do not edit.

package configurehelp;

use strict;
use warnings;
use Exporter;

use vars qw(
    @ISA
    @EXPORT_OK
    \$Cpreprocessor
    );

@ISA = qw(Exporter);

@EXPORT_OK = qw(
    \$Cpreprocessor
    );

\$Cpreprocessor = '${_cpp_cmd}';

1;
")

# Save build info for test runner to pick up and log
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/buildinfo.txt" "# This is a generated file.  Do not edit.
configure.tool: cmake
configure.command: ${CMAKE_COMMAND}
configure.version: ${CMAKE_VERSION}
configure.os: ${CMAKE_SYSTEM}
configure.args:${_cmake_args}
configure.generator: ${CMAKE_GENERATOR}
configure.make: ${CMAKE_MAKE_PROGRAM}
host.os: ${CMAKE_HOST_SYSTEM_NAME}
host.cpu: ${CMAKE_HOST_SYSTEM_PROCESSOR}
target: ${CMAKE_C_COMPILER_TARGET}
target.os: ${CMAKE_SYSTEM_NAME}
target.cpu: ${CMAKE_SYSTEM_PROCESSOR}
target.flags:${_target_flags}
compiler: ${CMAKE_C_COMPILER_ID}
compiler.version: ${CMAKE_C_COMPILER_VERSION}
")

add_runtests(test-quiet     "-a -s")
add_runtests(test-am        "-a -am")
add_runtests(test-full      "-a -p -r")
# ~flaky means that it ignores results of tests using the flaky keyword
add_runtests(test-nonflaky  "-a -p ~flaky ~timing-dependent")
add_runtests(test-ci        "-a -p ~flaky ~timing-dependent -r -rm -j2")
add_runtests(test-torture   "-a -t")
add_runtests(test-event     "-a -e")
