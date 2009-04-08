
FUNCTION(SETUP_TEST TEST_NAME)		# ARGN are the files in the test
	ADD_EXECUTABLE( ${TEST_NAME} ${ARGN} )
	STRING(TOUPPER ${TEST_NAME} UPPER_TEST_NAME)

	INCLUDE_DIRECTORIES(
		${CURL_SOURCE_DIR}/lib		# To be able to reach "setup_once.h"
		${CURL_BINARY_DIR}/lib		# To be able to reach "config.h"
		${CURL_BINARY_DIR}/include	# To be able to reach "curl/curlbuild.h"
	)

	SETUP_CURL_DEPENDENCIES(${TEST_NAME})
	TARGET_LINK_LIBRARIES( ${TEST_NAME} libcurl )

	SET_TARGET_PROPERTIES(${TEST_NAME} PROPERTIES COMPILE_DEFINITIONS ${UPPER_TEST_NAME})

	# Add the postfix to the executable since it is not added automatically as for modules and shared libraries
	SET_TARGET_PROPERTIES(${TEST_NAME} PROPERTIES DEBUG_POSTFIX "${CMAKE_DEBUG_POSTFIX}")

	IF(MSVC)
		IF(NOT BUILD_RELEASE_DEBUG_DIRS)
			# Ugly workaround to remove the "/debug" or "/release" in each output
			SET_TARGET_PROPERTIES(${TEST_NAME} PROPERTIES PREFIX "../")
			SET_TARGET_PROPERTIES(${TEST_NAME} PROPERTIES IMPORT_PREFIX "../")
		ENDIF()
	ENDIF()

ENDFUNCTION()


TRANSFORM_MAKEFILE_INC("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
INCLUDE(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

FOREACH(TEST_NAME ${noinst_PROGRAMS})
	SETUP_TEST(${TEST_NAME} ${${TEST_NAME}_SOURCES})
ENDFOREACH()


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
	# lib539 lib557 lib558
	# #lib559
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
		# LIST(APPEND SOURCE ${TESTUTIL})		# Need TestUtil
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

# SET(TEST_NAME lib559)
# SET(SOURCE "lib558.c" ${SUPPORTFILES})
# ADD_TESTUTIL_IF_NECESSARY(${TEST_NAME})
# SETUP_TEST(${TEST_NAME} ${SOURCE})
