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
set(TARGET_LABEL_PREFIX "Test ")

function(setup_test TEST_NAME)          # ARGN are the files in the test
  add_executable( ${TEST_NAME} ${ARGN} )
  string(TOUPPER ${TEST_NAME} UPPER_TEST_NAME)

  include_directories(
    ${CURL_SOURCE_DIR}/lib          # To be able to reach "curl_setup_once.h"
    ${CURL_BINARY_DIR}/lib          # To be able to reach "curl_config.h"
    ${CURL_BINARY_DIR}/include      # To be able to reach "curl/curl.h"
    ${CURL_SOURCE_DIR}/tests/libtest # To be able to build generated tests
    )
  if(USE_ARES)
    include_directories(${CARES_INCLUDE_DIR})
  endif()

  target_link_libraries(${TEST_NAME} libcurl ${CURL_LIBS})

  set_target_properties(${TEST_NAME}
    PROPERTIES COMPILE_DEFINITIONS ${UPPER_TEST_NAME})
  set_target_properties(${TEST_NAME}
    PROPERTIES PROJECT_LABEL "${TARGET_LABEL_PREFIX}${TEST_NAME}")
endfunction()


transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

foreach(TEST_NAME ${noinst_PROGRAMS})
  if(DEFINED ${TEST_NAME}_SOURCES)
    setup_test(${TEST_NAME} ${${TEST_NAME}_SOURCES})
  else()
    setup_test(${TEST_NAME} ${nodist_${TEST_NAME}_SOURCES})
  endif()
endforeach()

# Allows for hostname override to make tests machine independent.
# TODO this cmake build assumes a shared build, detect static linking here!
if(NOT WIN32)
  add_library(hostname MODULE sethostname.c sethostname.h)
  # Output to .libs for compatibility with autotools, the test data expects a
  # library at (tests)/libtest/.libs/libhostname.so
  set_target_properties(hostname PROPERTIES
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/.libs)
  if(HIDES_CURL_PRIVATE_SYMBOLS)
    set_property(TARGET hostname APPEND PROPERTY COMPILE_DEFINITIONS "CURL_HIDDEN_SYMBOLS")
    set_property(TARGET hostname APPEND PROPERTY COMPILE_FLAGS ${CURL_CFLAG_SYMBOLS_HIDE})
  endif()
endif()

add_custom_command(
  OUTPUT lib1521.c
  COMMAND ${PERL_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl < ${CURL_SOURCE_DIR}/include/curl/curl.h > lib1521.c
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mk-lib1521.pl"
    "${CURL_SOURCE_DIR}/include/curl/curl.h"
  VERBATIM)

set_property(TARGET chkdecimalpoint
  APPEND PROPERTY COMPILE_DEFINITIONS "CURLX_NO_MEMORY_CALLBACKS;CURL_STATICLIB")

  # # files used only in some libcurl test programs
# SET(TESTUTIL testutil.c testutil.h)

# # these files are used in every single test program below
# SET(SUPPORTFILES first.c test.h)

# # These are all libcurl test programs
# SET(noinst_PROGRAMS
# lib500 lib501 lib502 lib503 lib504 lib505 lib506
# lib507 lib508 lib510 lib511 lib512 lib513 lib514 lib515 lib516
# lib517 lib518 lib519 lib520 lib521 lib523 lib524 lib525 lib526
# #lib527
# #lib529
# lib530
# #lib532
# lib533 lib536 lib537 lib540 lib541 lib542 lib543
# lib544
# #lib545
# lib547
# #lib548
# lib549 lib552 lib553 lib554 lib555 lib556
# lib539 lib557
# lib560
# )

# SET(noinst_PROGRAMS_USE_TESTUTIL
# lib502 lib503 lib504
# lib507
# lib525 lib526 lib527
# lib529
# lib530
# lib532
# lib533 lib536
# lib555
# )

# MACRO(ADD_TESTUTIL_IF_NECESSARY TEST_NAME)
# LIST(FIND noinst_PROGRAMS_USE_TESTUTIL ${TEST_NAME} USES_TESTUTIL)
# IF(NOT ${USES_TESTUTIL} EQUAL -1)
# LIST(APPEND SOURCE ${TESTUTIL})               # Need TestUtil
# ENDIF()
# ENDMACRO()

# # General case
# FOREACH(TEST_NAME ${noinst_PROGRAMS})
# SET(SOURCE "${TEST_NAME}.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})
# ENDFOREACH()

# # Special cases
# SET(TEST_NAME lib527)
# SET(SOURCE "lib526.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})

# SET(TEST_NAME lib529)
# SET(SOURCE "lib525.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})

# SET(TEST_NAME lib532)
# SET(SOURCE "lib526.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})

# SET(TEST_NAME lib545)
# SET(SOURCE "lib544.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})

# SET(TEST_NAME lib548)
# SET(SOURCE "lib547.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})
