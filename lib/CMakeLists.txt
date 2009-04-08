SET(LIB_NAME libcurl)

CONFIGURE_FILE(${CURL_SOURCE_DIR}/include/curl/curlbuild.h.cmake
  ${CURL_BINARY_DIR}/include/curl/curlbuild.h)
CONFIGURE_FILE(config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)


TRANSFORM_MAKEFILE_INC("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
INCLUDE(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

LIST(APPEND HHEADERS
	${CMAKE_CURRENT_BINARY_DIR}/config.h
	${CURL_BINARY_DIR}/include/curl/curlbuild.h
)

IF(MSVC)
	LIST(APPEND CSOURCES libcurl.rc)
ENDIF()

# SET(CSOURCES
  # #  memdebug.c -not used
  # # nwlib.c - Not used
  # # strtok.c - specify later
  # # strtoofft.c - specify later
# )

# # if we have Kerberos 4, right now this is never on
# #OPTION(CURL_KRB4 "Use Kerberos 4" OFF)
# IF(CURL_KRB4)
  # SET(CSOURCES ${CSOURCES}
    # krb4.c
    # security.c
    # )
# ENDIF(CURL_KRB4)

# #OPTION(CURL_MALLOC_DEBUG "Debug mallocs in Curl" OFF)
# MARK_AS_ADVANCED(CURL_MALLOC_DEBUG)
# IF(CURL_MALLOC_DEBUG)
  # SET(CSOURCES ${CSOURCES}
    # memdebug.c
    # )
# ENDIF(CURL_MALLOC_DEBUG)

# # only build compat strtoofft if we need to
# IF(NOT HAVE_STRTOLL AND NOT HAVE__STRTOI64)
  # SET(CSOURCES ${CSOURCES}
    # strtoofft.c
    # )
# ENDIF(NOT HAVE_STRTOLL AND NOT HAVE__STRTOI64)

IF(HAVE_FEATURES_H)
  SET_SOURCE_FILES_PROPERTIES(
    cookie.c
    easy.c
    formdata.c
    getenv.c
    hash.c
    http.c
    if2ip.c 
    mprintf.c
    multi.c
    sendf.c
    telnet.c
    transfer.c
    url.c
    COMPILE_FLAGS -D_BSD_SOURCE)
ENDIF(HAVE_FEATURES_H)


# The rest of the build

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/../include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/../include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/..)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

IF(CURL_STATICLIB)
	# Static lib
	SET(CURL_USER_DEFINED_DYNAMIC_OR_STATIC STATIC)
ELSE()
	# DLL / so dynamic lib
	SET(CURL_USER_DEFINED_DYNAMIC_OR_STATIC SHARED)
ENDIF()

ADD_LIBRARY(
	${LIB_NAME}
	${CURL_USER_DEFINED_DYNAMIC_OR_STATIC}
	${HHEADERS} ${CSOURCES}
)

TARGET_LINK_LIBRARIES(${LIB_NAME} ${CURL_LIBS})

IF(WIN32)
	ADD_DEFINITIONS( -D_USRDLL )
ENDIF()

SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES COMPILE_DEFINITIONS BUILDING_LIBCURL)

SETUP_CURL_DEPENDENCIES(${LIB_NAME})

# Remove the "lib" prefix since the library is already named "libcurl".
SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES PREFIX "")
SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES IMPORT_PREFIX "")

IF(MSVC)
	IF(NOT BUILD_RELEASE_DEBUG_DIRS)
		# Ugly workaround to remove the "/debug" or "/release" in each output
		SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES PREFIX "../")
		SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES IMPORT_PREFIX "../")
	ENDIF()
ENDIF()

IF(WIN32)
	IF(NOT CURL_STATICLIB)
		# Add "_imp" as a suffix before the extension to avoid conflicting with the statically linked "libcurl.lib"
		SET_TARGET_PROPERTIES(${LIB_NAME} PROPERTIES IMPORT_SUFFIX "_imp.lib")
	ENDIF()
ENDIF()
