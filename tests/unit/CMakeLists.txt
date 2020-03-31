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

set(UT_SRC
  unit1300.c
  unit1301.c
  unit1302.c
  unit1303.c
  unit1304.c
  unit1305.c
  unit1307.c
  unit1308.c
  unit1309.c
  unit1330.c
# Broken link on Linux
#  unit1394.c
  unit1395.c
  unit1396.c
  unit1397.c
  unit1398.c
  unit1600.c
  unit1601.c
  unit1603.c
# Broken link on Linux
#  unit1604.c
  unit1620.c
  unit1655.c
  )

set(UT_COMMON_FILES ../libtest/first.c ../libtest/test.h curlcheck.h)
include_directories(
  ${CURL_SOURCE_DIR}/lib          # To be able to reach "curl_setup_once.h"
  ${CURL_SOURCE_DIR}/tests/libtest
  ${CURL_SOURCE_DIR}/src
  ${CURL_BINARY_DIR}/lib          # To be able to reach "curl_config.h"
  ${CURL_BINARY_DIR}/include      # To be able to reach "curl/curl.h"
)

foreach(_testfile ${UT_SRC})

  get_filename_component(_testname ${_testfile} NAME_WE)
  add_executable(${_testname} ${_testfile} ${UT_COMMON_FILES})
  target_link_libraries(${_testname} libcurl ${CURL_LIBS})
  set_target_properties(${_testname}
      PROPERTIES COMPILE_DEFINITIONS "UNITTESTS")

  if(HIDES_CURL_PRIVATE_SYMBOLS)
    set_target_properties(${_testname}
      PROPERTIES
      EXCLUDE_FROM_ALL TRUE
      EXCLUDE_FROM_DEFAULT_BUILD TRUE
    )
  else()
    add_test(NAME ${_testname}
             COMMAND ${_testname} "http://www.google.com"
    )
  endif()
endforeach()
