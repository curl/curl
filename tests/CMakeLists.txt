#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
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

add_runtests(test           "")
add_runtests(test-quiet     "-a -s")
add_runtests(test-am        "-a -am")
add_runtests(test-full      "-a -p -r")
# !flaky means that it'll skip all tests using the flaky keyword
add_runtests(test-nonflaky  "-a -p !flaky")
add_runtests(test-torture   "-a -t")
add_runtests(test-event     "-a -e")
