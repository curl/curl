set(EXE_NAME curl)

# First try to locate hugehelp.c to see if it has already been created
# TODO Find the file WITHOUT adding a cache entry!!! Or else the user can delete the file after the script was first run, and the script won't notice it has gone.
find_file(HUGEHELP_C_FILE hugehelp.c PATHS . NO_DEFAULT_PATH)
if (NOT HUGEHELP_C_FILE)
  message(STATUS "Warning: hugehelp.c file was not generated before. Generating an 'empty' file...")
  file(WRITE hugehelp.c "/* built-in manual is disabled, blank function */\n#include \"hugehelp.h\"\nvoid hugehelp(void) {}\n\n")
endif()

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

if(MSVC)
  list(APPEND CURL_SOURCE curl.rc)
endif()

add_executable(
  ${EXE_NAME}
  ${curl_SOURCES}
  )

source_group("cURLX source files" FILES ${CURLX_ONES})
source_group("cURL source files" FILES ${CURL_CFILES})
source_group("cURL header files" FILES ${CURL_HFILES})

include_directories(
  ${CURL_SOURCE_DIR}/lib                # To be able to reach "setup_once.h"
  ${CURL_BINARY_DIR}/lib                # To be able to reach "curl_config.h"
  ${CURL_BINARY_DIR}/include    # To be able to reach "curl/curlbuild.h"
  )


# Setup dependencies
setup_curl_dependencies(${EXE_NAME})
target_link_libraries( ${EXE_NAME} libcurl )


################################################################################

#SET_TARGET_PROPERTIES(${EXE_NAME} ARCHIVE_OUTPUT_DIRECTORY "blah blah blah")
#SET_TARGET_PROPERTIES(${EXE_NAME} RUNTIME_OUTPUT_DIRECTORY "blah blah blah")
#SET_TARGET_PROPERTIES(${EXE_NAME} LIBRARY_OUTPUT_DIRECTORY "blah blah blah")

# Add the postfix to the executable since it is not added automatically as for modules and shared libraries
set_target_properties(${EXE_NAME} PROPERTIES
  DEBUG_POSTFIX "${CMAKE_DEBUG_POSTFIX}")

if(MSVC)
  if(NOT BUILD_RELEASE_DEBUG_DIRS)
    # Ugly workaround to remove the "/debug" or "/release" in each output
    set_target_properties(${EXE_NAME} PROPERTIES PREFIX "../")
  endif()
endif()

#INCLUDE(ModuleInstall OPTIONAL)

install(TARGETS ${EXE_NAME} DESTINATION bin)
