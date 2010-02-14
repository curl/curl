set(LIB_NAME libcurl)

configure_file(${CURL_SOURCE_DIR}/include/curl/curlbuild.h.cmake
  ${CURL_BINARY_DIR}/include/curl/curlbuild.h)
configure_file(curl_config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h)

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

list(APPEND HHEADERS
  ${CMAKE_CURRENT_BINARY_DIR}/curl_config.h
  ${CURL_BINARY_DIR}/include/curl/curlbuild.h
  )

if(MSVC)
  list(APPEND CSOURCES libcurl.rc)
endif()

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

if(HAVE_FEATURES_H)
  set_source_files_properties(
    cookie.c
    easy.c
    formdata.c
    getenv.c
    nonblock.c
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
endif(HAVE_FEATURES_H)


# The rest of the build

include_directories(${CMAKE_CURRENT_BINARY_DIR}/../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
if(CURL_USE_ARES)
  include_directories(${CARES_INCLUDE_DIR})
endif()

if(CURL_STATICLIB)
  # Static lib
  set(CURL_USER_DEFINED_DYNAMIC_OR_STATIC STATIC)
else()
  # DLL / so dynamic lib
  set(CURL_USER_DEFINED_DYNAMIC_OR_STATIC SHARED)
endif()

add_library(
  ${LIB_NAME}
  ${CURL_USER_DEFINED_DYNAMIC_OR_STATIC}
  ${HHEADERS} ${CSOURCES}
  )

target_link_libraries(${LIB_NAME} ${CURL_LIBS})

if(WIN32)
  add_definitions( -D_USRDLL )
endif()

set_target_properties(${LIB_NAME} PROPERTIES COMPILE_DEFINITIONS BUILDING_LIBCURL)

setup_curl_dependencies(${LIB_NAME})

# Remove the "lib" prefix since the library is already named "libcurl".
set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
set_target_properties(${LIB_NAME} PROPERTIES IMPORT_PREFIX "")

if(MSVC)
  if(NOT BUILD_RELEASE_DEBUG_DIRS)
    # Ugly workaround to remove the "/debug" or "/release" in each output
    set_target_properties(${LIB_NAME} PROPERTIES PREFIX "../")
    set_target_properties(${LIB_NAME} PROPERTIES IMPORT_PREFIX "../")
  endif()
endif()

if(WIN32)
  if(NOT CURL_STATICLIB)
    # Add "_imp" as a suffix before the extension to avoid conflicting with the statically linked "libcurl.lib"
    set_target_properties(${LIB_NAME} PROPERTIES IMPORT_SUFFIX "_imp.lib")
  endif()
endif()
