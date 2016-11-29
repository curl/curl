set(TARGET_LABEL_PREFIX "Test server ")

function(SETUP_EXECUTABLE TEST_NAME)    # ARGN are the files in the test
  add_executable( ${TEST_NAME} ${ARGN} )
  string(TOUPPER ${TEST_NAME} UPPER_TEST_NAME)

  include_directories(
    ${CURL_SOURCE_DIR}/lib      # To be able to reach "curl_setup_once.h"
    ${CURL_BINARY_DIR}/lib      # To be able to reach "curl_config.h"
    ${CURL_BINARY_DIR}/include  # To be able to reach "curl/curlbuild.h"
    )
  if(USE_ARES)
    include_directories(${CARES_INCLUDE_DIR})
  endif()

  target_link_libraries(${TEST_NAME} ${CURL_LIBS})

  # Test servers simply are standalone programs that do not use libcurl
  # library.  For convinience and to ease portability of these servers,
  # some source code files from the libcurl subdirectory are also used
  # to build the servers.  In order to achieve proper linkage of these
  # files on Win32 targets it is necessary to build the test servers
  # with CURL_STATICLIB defined, independently of how libcurl is built.
  if(NOT CURL_STATICLIB)
    set_target_properties(${TEST_NAME} PROPERTIES
      COMPILE_DEFINITIONS CURL_STATICLIB)       # ${UPPER_TEST_NAME}
  endif()
  set_target_properties(${TEST_NAME} PROPERTIES
    PROJECT_LABEL "${TARGET_LABEL_PREFIX}${TEST_NAME}")

  # Add the postfix to the executable since it is not added
  # automatically as for modules and shared libraries
  set_target_properties(${TEST_NAME} PROPERTIES
    DEBUG_POSTFIX "${CMAKE_DEBUG_POSTFIX}")

endfunction()


transform_makefile_inc("Makefile.inc"
  "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

foreach(EXECUTABLE_NAME ${noinst_PROGRAMS})
  setup_executable(${EXECUTABLE_NAME} ${${EXECUTABLE_NAME}_SOURCES})
endforeach()


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

