#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
set(EXE_NAME curl)
add_definitions(-DBUILDING_CURL)

if(ENABLE_CURL_MANUAL AND HAVE_MANUAL_TOOLS)
  add_definitions("-DUSE_MANUAL")
  add_custom_command(
    OUTPUT tool_hugehelp.c
    COMMAND ${CMAKE_COMMAND} -E echo "#include \"tool_setup.h\"" > tool_hugehelp.c
    COMMAND ${CMAKE_COMMAND} -E echo "#ifndef HAVE_LIBZ" >> tool_hugehelp.c
    COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl" < "${CURL_BINARY_DIR}/docs/cmdline-opts/curl.txt" >> tool_hugehelp.c

    COMMAND ${CMAKE_COMMAND} -E echo "#else" >> tool_hugehelp.c
    COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl" -c < "${CURL_BINARY_DIR}/docs/cmdline-opts/curl.txt" >> tool_hugehelp.c
    COMMAND ${CMAKE_COMMAND} -E echo "#endif /* HAVE_LIBZ */" >> tool_hugehelp.c
    DEPENDS
      generate-curl.1
      "${CURL_BINARY_DIR}/docs/cmdline-opts/curl.1"
      "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl"
      "${CMAKE_CURRENT_SOURCE_DIR}/tool_hugehelp.h"
    VERBATIM)
else()
  add_custom_command(
    OUTPUT tool_hugehelp.c
    COMMAND ${CMAKE_COMMAND} -E echo "#include \"tool_hugehelp.h\"" > tool_hugehelp.c
    DEPENDS
      "${CMAKE_CURRENT_SOURCE_DIR}/tool_hugehelp.h"
    VERBATIM)

endif()

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

if(WIN32)
  list(APPEND CURL_CFILES curl.rc)
endif()

# CURL_CFILES, CURLX_CFILES, CURL_HFILES, CURLTOOL_LIBCURL_CFILES
# come from Makefile.inc
if(BUILD_STATIC_CURL)
  set(CURLX_CFILES ${CURLTOOL_LIBCURL_CFILES})
endif()

if(ENABLE_CURLDEBUG)
  # We must compile this source separately to avoid memdebug.h redefinitions
  # applying to them.
  set_source_files_properties(../lib/curl_multibyte.c PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
endif()

add_executable(
  ${EXE_NAME}
  ${CURL_CFILES} ${CURLX_CFILES} ${CURL_HFILES}
  )

add_executable(
  ${PROJECT_NAME}::${EXE_NAME}
  ALIAS ${EXE_NAME}
  )

add_library(
  curltool  # special libcurltool library just for unittests
  STATIC
  EXCLUDE_FROM_ALL
  ${CURL_CFILES} ${CURLTOOL_LIBCURL_CFILES} ${CURL_HFILES}
)
target_compile_definitions(curltool PUBLIC UNITTESTS CURL_STATICLIB)
target_link_libraries(curltool PRIVATE ${CURL_LIBS})

if(CURL_HAS_LTO)
  set_target_properties(${EXE_NAME} PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
endif()

if(ENABLE_UNICODE AND MINGW)
  target_link_libraries(${EXE_NAME} -municode)
endif()

source_group("curlX source files" FILES ${CURLX_CFILES})
source_group("curl source files" FILES ${CURL_CFILES})
source_group("curl header files" FILES ${CURL_HFILES})

include_directories(
  ${CURL_SOURCE_DIR}/lib      # for "curl_setup_once.h"
  ${CURL_BINARY_DIR}/lib      # for "curl_config.h"
  ${CURL_BINARY_DIR}/include  # for "curl/curl.h"
  # This is needed as tool_hugehelp.c is generated in the binary dir
  ${CURL_SOURCE_DIR}/src      # for "tool_hugehelp.h"
  )

# Build curl executable
target_link_libraries(${EXE_NAME} ${LIB_SELECTED_FOR_EXE} ${CURL_LIBS})

################################################################################

#set_target_properties(${EXE_NAME} ARCHIVE_OUTPUT_DIRECTORY "blah blah blah")
#set_target_properties(${EXE_NAME} RUNTIME_OUTPUT_DIRECTORY "blah blah blah")
#set_target_properties(${EXE_NAME} LIBRARY_OUTPUT_DIRECTORY "blah blah blah")

#include(ModuleInstall OPTIONAL)

install(TARGETS ${EXE_NAME} EXPORT ${TARGETS_EXPORT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
export(TARGETS ${EXE_NAME}
       FILE ${PROJECT_BINARY_DIR}/curl-target.cmake
       NAMESPACE ${PROJECT_NAME}::
)
