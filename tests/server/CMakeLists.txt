
FUNCTION(SETUP_EXECUTABLE TEST_NAME)		# ARGN are the files in the test
	ADD_EXECUTABLE( ${TEST_NAME} ${ARGN} )
	STRING(TOUPPER ${TEST_NAME} UPPER_TEST_NAME)

	INCLUDE_DIRECTORIES(
		${CURL_SOURCE_DIR}/lib		# To be able to reach "setup_once.h"
		${CURL_BINARY_DIR}/lib		# To be able to reach "config.h"
		${CURL_BINARY_DIR}/include	# To be able to reach "curl/curlbuild.h"
	)

	SETUP_CURL_DEPENDENCIES(${TEST_NAME})
	#TARGET_LINK_LIBRARIES( ${TEST_NAME} libcurl )

	#SET_TARGET_PROPERTIES(${TEST_NAME} PROPERTIES COMPILE_DEFINITIONS ${UPPER_TEST_NAME})

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

FOREACH(EXECUTABLE_NAME ${noinst_PROGRAMS})
	SETUP_EXECUTABLE(${EXECUTABLE_NAME} ${${EXECUTABLE_NAME}_SOURCES})
ENDFOREACH()


# SET(useful
	# getpart.c getpart.h
	# ${CURL_SOURCE_DIR}/lib/strequal.c
	# ${CURL_SOURCE_DIR}/lib/base64.c
	# ${CURL_SOURCE_DIR}/lib/mprintf.c
	# ${CURL_SOURCE_DIR}/lib/memdebug.c
	# ${CURL_SOURCE_DIR}/lib/timeval.c
# )

# SETUP_EXECUTABLE(sws sws.c util.c util.h ${useful})
# SETUP_EXECUTABLE(resolve resolve.c util.c util.h ${useful})
# SETUP_EXECUTABLE(sockfilt sockfilt.c util.c util.h ${useful} ${CURL_SOURCE_DIR}/lib/inet_pton.c)
# SETUP_EXECUTABLE(getpart testpart.c ${useful})
# SETUP_EXECUTABLE(tftpd tftpd.c util.c util.h ${useful} tftp.h)

