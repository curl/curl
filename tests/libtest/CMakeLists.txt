set(TARGET_LABEL_PREFIX "Test ")

function(SETUP_TEST TEST_NAME)          # ARGN are the files in the test
  add_executable( ${TEST_NAME} ${ARGN} )
  string(TOUPPER ${TEST_NAME} UPPER_TEST_NAME)

  include_directories(
    ${CURL_SOURCE_DIR}/lib          # To be able to reach "curl_setup_once.h"
    ${CURL_BINARY_DIR}/lib          # To be able to reach "curl_config.h"
    ${CURL_BINARY_DIR}/include      # To be able to reach "curl/curlbuild.h"
    )
  if(CURL_USE_ARES)
    include_directories(${CARES_INCLUDE_DIR})
  endif()
  setup_curl_dependencies(${TEST_NAME})
  target_link_libraries( ${TEST_NAME} libcurl )

  set_target_properties(${TEST_NAME}
    PROPERTIES COMPILE_DEFINITIONS ${UPPER_TEST_NAME})
  set_target_properties(${TEST_NAME}
    PROPERTIES PROJECT_LABEL "${TARGET_LABEL_PREFIX}${TEST_NAME}")

  # Add the postfix to the executable since it is
  # not added automatically as for modules and shared libraries
  set_target_properties(${TEST_NAME}
    PROPERTIES DEBUG_POSTFIX "${CMAKE_DEBUG_POSTFIX}")

endfunction()


transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

foreach(TEST_NAME ${noinst_PROGRAMS})
  setup_test(${TEST_NAME} ${${TEST_NAME}_SOURCES})
endforeach()


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
