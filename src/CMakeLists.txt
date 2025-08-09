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

set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS "${CURL_DEBUG_MACROS}")

set(_curl_cfiles_gen "")
set(_curl_hfiles_gen "")
set(_curl_definitions "")

if(ENABLE_CURL_MANUAL AND (PERL_FOUND OR EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tool_hugehelp.c"))
  if(PERL_FOUND)
    add_custom_command(OUTPUT "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "#include \"tool_setup.h\"" > "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "/* !checksrc! disable COPYRIGHT all */" >> "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "/* !checksrc! disable INCLUDEDUP all */" >> "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "/* !checksrc! disable LONGLINE all */" >> "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "#ifndef HAVE_LIBZ" >> "tool_hugehelp.c"
      COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl"    < "${CURL_ASCIIPAGE}" >> "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "#else" >> "tool_hugehelp.c"
      COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl" -c < "${CURL_ASCIIPAGE}" >> "tool_hugehelp.c"
      COMMAND ${CMAKE_COMMAND} -E echo "#endif /* HAVE_LIBZ */" >> "tool_hugehelp.c"
      DEPENDS
        generate-curl.1
        "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl"
        "${CMAKE_CURRENT_SOURCE_DIR}/tool_hugehelp.h"
        "${CURL_ASCIIPAGE}"
      VERBATIM)
  else()
    message(STATUS "Perl not found. Using the pre-built tool_hugehelp.c found in the source tree.")
  endif()
  list(APPEND _curl_cfiles_gen "tool_hugehelp.c")
  list(APPEND _curl_hfiles_gen "tool_hugehelp.h")
  list(APPEND _curl_definitions "USE_MANUAL")
endif()

if(CURL_CA_EMBED_SET)
  if(PERL_FOUND)
    add_custom_command(OUTPUT "tool_ca_embed.c"
      COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mk-file-embed.pl" --var curl_ca_embed
        < "${CURL_CA_EMBED}" > "tool_ca_embed.c"
      DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/mk-file-embed.pl"
        "${CURL_CA_EMBED}"
      VERBATIM)
    list(APPEND _curl_cfiles_gen "tool_ca_embed.c")
    list(APPEND _curl_definitions "CURL_CA_EMBED")
  else()
    message(WARNING "Perl not found. Will not embed the CA bundle.")
  endif()
endif()

# Get CURL_CFILES, CURL_HFILES, CURLX_CFILES, CURLX_HFILES, CURL_RCFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

source_group("curl source files" FILES ${CURL_CFILES} ${_curl_cfiles_gen})
source_group("curl header files" FILES ${CURL_HFILES} ${_curl_hfiles_gen})
source_group("curlx source files" FILES ${CURLX_CFILES})
source_group("curlx header files" FILES ${CURLX_HFILES})

if(WIN32)
  list(APPEND CURL_CFILES ${CURL_RCFILES})
endif()

set(_curlx_cfiles_lib ${CURLX_CFILES})
set(_curlx_hfiles_lib ${CURLX_HFILES})
if(LIB_SELECTED STREQUAL LIB_STATIC)
  set(_curlx_cfiles_lib "")
  set(_curlx_hfiles_lib "")
endif()

if(BUILD_STATIC_CURL)
  set(CURLX_CFILES "")
  set(CURLX_HFILES "")
endif()

set_property(DIRECTORY APPEND PROPERTY INCLUDE_DIRECTORIES
  "${PROJECT_BINARY_DIR}/lib"        # for "curl_config.h"
  "${PROJECT_SOURCE_DIR}/lib"        # for "curl_setup.h", curlx
  "${CMAKE_CURRENT_SOURCE_DIR}"      # for "tool_hugehelp.c"
)

# Build curl executable
add_executable(${EXE_NAME} ${CURL_CFILES} ${CURL_HFILES} ${_curl_cfiles_gen} ${_curl_hfiles_gen} ${CURLX_CFILES} ${CURLX_HFILES})
target_compile_definitions(${EXE_NAME} PRIVATE ${_curl_definitions})
target_link_libraries(${EXE_NAME} ${LIB_SELECTED_FOR_EXE} ${CURL_LIBS})

add_executable(${PROJECT_NAME}::${EXE_NAME} ALIAS ${EXE_NAME})

add_executable(curlinfo EXCLUDE_FROM_ALL "curlinfo.c")
set_target_properties(curlinfo PROPERTIES UNITY_BUILD OFF)

# special libcurltool library just for unittests
add_library(curltool STATIC EXCLUDE_FROM_ALL ${CURL_CFILES} ${CURL_HFILES} ${_curlx_cfiles_lib} ${_curlx_hfiles_lib})
target_compile_definitions(curltool PUBLIC "CURL_STATICLIB" "UNITTESTS")
target_link_libraries(curltool PRIVATE ${CURL_LIBS})
set_target_properties(curltool PROPERTIES C_CLANG_TIDY "")

if(CURL_HAS_LTO)
  set_target_properties(${EXE_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

if(ENABLE_UNICODE AND MINGW AND NOT MINGW32CE)
  if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
    target_link_options(${EXE_NAME} PRIVATE "-municode")
  else()
    target_link_libraries(${EXE_NAME} PRIVATE "-municode")
  endif()
endif()

################################################################################

install(TARGETS ${EXE_NAME} EXPORT ${TARGETS_EXPORT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
export(TARGETS ${EXE_NAME}
  FILE "${PROJECT_BINARY_DIR}/curl-target.cmake"
  NAMESPACE ${PROJECT_NAME}::
)
