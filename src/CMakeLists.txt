SET(EXE_NAME curl)

# First try to locate hugehelp.c to see if it has already been created
# TODO Find the file WITHOUT adding a cache entry!!! Or else the user can delete the file after the script was first run, and the script won't notice it has gone.
FIND_FILE(HUGEHELP_C_FILE hugehelp.c PATHS . NO_DEFAULT_PATH)
IF (NOT HUGEHELP_C_FILE)
	MESSAGE(STATUS "Warning: hugehelp.c file was not generated before. Generating an 'empty' file...")
	FILE(WRITE hugehelp.c "/* built-in manual is disabled, blank function */\n#include \"hugehelp.h\"\nvoid hugehelp(void) {}")
ENDIF()

SET(CURLX_SOURCE
	${CURL_SOURCE_DIR}/lib/strtoofft.c
	${CURL_SOURCE_DIR}/lib/strdup.c
	${CURL_SOURCE_DIR}/lib/rawstr.c
)

SET(CURL_SOURCE
	main.c hugehelp.c urlglob.c writeout.c writeenv.c
	getpass.c homedir.c curlutil.c
)

SET(CURL_HEADERS
	hugehelp.h setup.h config-win32.h config-mac.h
	config-riscos.h urlglob.h version.h
	writeout.h writeenv.h getpass.h homedir.h curlutil.h
)

IF(MSVC)
	LIST(APPEND CURL_SOURCE curl.rc)
ENDIF()

ADD_EXECUTABLE(
	${EXE_NAME}
    ${CURL_HEADERS}
	${CURL_SOURCE} ${CURLX_SOURCE}
)

SOURCE_GROUP("cURLX source files" FILES ${CURLX_SOURCE})
SOURCE_GROUP("cURL source files" FILES ${CURL_SOURCE})
SOURCE_GROUP("cURL header files" FILES ${CURL_HEADERS})

INCLUDE_DIRECTORIES(
    ${CURL_SOURCE_DIR}/lib		# To be able to reach "setup_once.h"
    ${CURL_BINARY_DIR}/lib		# To be able to reach "config.h"
	${CURL_BINARY_DIR}/include	# To be able to reach "curl/curlbuild.h"
)


# Setup dependencies
SETUP_CURL_DEPENDENCIES(${EXE_NAME})
TARGET_LINK_LIBRARIES( ${EXE_NAME} libcurl )


################################################################################

#SET_TARGET_PROPERTIES(${EXE_NAME} ARCHIVE_OUTPUT_DIRECTORY "blah blah blah")
#SET_TARGET_PROPERTIES(${EXE_NAME} RUNTIME_OUTPUT_DIRECTORY "blah blah blah")
#SET_TARGET_PROPERTIES(${EXE_NAME} LIBRARY_OUTPUT_DIRECTORY "blah blah blah")

# Add the postfix to the executable since it is not added automatically as for modules and shared libraries
SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES DEBUG_POSTFIX "${CMAKE_DEBUG_POSTFIX}")

IF(MSVC)
	IF(NOT BUILD_RELEASE_DEBUG_DIRS)
		# Ugly workaround to remove the "/debug" or "/release" in each output
		SET_TARGET_PROPERTIES(${EXE_NAME} PROPERTIES PREFIX "../")
	ENDIF()
ENDIF()

#INCLUDE(ModuleInstall OPTIONAL)
