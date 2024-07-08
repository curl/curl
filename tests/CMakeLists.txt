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

add_custom_target(testdeps)
add_subdirectory(data)
add_subdirectory(libtest)
add_subdirectory(server)
add_subdirectory(unit)

function(add_runtests targetname test_flags)
  # Use a special '$TFLAGS' placeholder as last argument which will be
  # replaced by the contents of the environment variable in runtests.pl.
  # This is a workaround for CMake's limitation where commands executed by
  # 'make' or 'ninja' cannot portably reference environment variables.
  string(REPLACE " " ";" test_flags_list "${test_flags}")
  add_custom_target(${targetname}
    COMMAND
      "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/runtests.pl"
      ${test_flags_list}
      "\$TFLAGS"
    DEPENDS testdeps
    VERBATIM USES_TERMINAL
  )
endfunction()

# Create configurehelp.pm, used by tests needing to run the C preprocessor.
if(MSVC OR CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
  set(_cpp_cmd "\"${CMAKE_C_COMPILER}\" -E")
  if(APPLE AND NOT CMAKE_OSX_SYSROOT STREQUAL "")
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

add_runtests(test-quiet     "-a -s")
add_runtests(test-am        "-a -am")
add_runtests(test-full      "-a -p -r")
# ~flaky means that it'll ignore results of tests using the flaky keyword
add_runtests(test-nonflaky  "-a -p ~flaky ~timing-dependent")
add_runtests(test-ci        "-a -p ~flaky ~timing-dependent -r -rm")
add_runtests(test-torture   "-a -t")
add_runtests(test-event     "-a -e")
