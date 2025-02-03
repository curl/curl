#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
set(EXE_NAME fetch)
add_definitions("-DBUILDING_FETCH")

set(_fetch_cfiles_gen "")
set(_fetch_hfiles_gen "")
set(_fetch_definitions "")

if(ENABLE_FETCH_MANUAL AND HAVE_MANUAL_TOOLS)
  list(APPEND _fetch_definitions "USE_MANUAL")
  add_custom_command(
    OUTPUT "tool_hugehelp.c"
    COMMAND ${CMAKE_COMMAND} -E echo "#include \"tool_setup.h\"" > "tool_hugehelp.c"
    COMMAND ${CMAKE_COMMAND} -E echo "#ifndef HAVE_LIBZ" >> "tool_hugehelp.c"
    COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl"    < "${FETCH_ASCIIPAGE}" >> "tool_hugehelp.c"
    COMMAND ${CMAKE_COMMAND} -E echo "#else" >> "tool_hugehelp.c"
    COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl" -c < "${FETCH_ASCIIPAGE}" >> "tool_hugehelp.c"
    COMMAND ${CMAKE_COMMAND} -E echo "#endif /* HAVE_LIBZ */" >> "tool_hugehelp.c"
    DEPENDS
      generate-fetch.1
      "${CMAKE_CURRENT_SOURCE_DIR}/mkhelp.pl"
      "${CMAKE_CURRENT_SOURCE_DIR}/tool_hugehelp.h"
      "${FETCH_ASCIIPAGE}"
    VERBATIM)
  list(APPEND _fetch_cfiles_gen "tool_hugehelp.c")
  list(APPEND _fetch_hfiles_gen "tool_hugehelp.h")
endif()

if(FETCH_CA_EMBED_SET)
  if(PERL_FOUND)
    list(APPEND _fetch_definitions "FETCH_CA_EMBED")
    add_custom_command(
      OUTPUT "tool_ca_embed.c"
      COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/mk-file-embed.pl" --var fetch_ca_embed
        < "${FETCH_CA_EMBED}" > "tool_ca_embed.c"
      DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/mk-file-embed.pl"
        "${FETCH_CA_EMBED}"
      VERBATIM)
    list(APPEND _fetch_cfiles_gen "tool_ca_embed.c")
  else()
    message(WARNING "Perl not found. Will not embed the CA bundle.")
  endif()
endif()

# Get 'FETCH_CFILES', 'FETCHX_CFILES', 'FETCH_HFILES', 'FETCHTOOL_LIBFETCH_CFILES' variables
fetch_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

if(WIN32)
  list(APPEND FETCH_CFILES "fetch.rc")
endif()

if(BUILD_STATIC_FETCH)
  set(FETCHX_CFILES ${FETCHTOOL_LIBFETCH_CFILES})
endif()

if(ENABLE_FETCHDEBUG)
  # We must compile this source separately to avoid memdebug.h redefinitions
  # applying to them.
  set_source_files_properties("../lib/fetch_multibyte.c" PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
endif()

add_executable(
  ${EXE_NAME}
  ${FETCH_CFILES} ${_fetch_cfiles_gen} ${FETCHX_CFILES} ${FETCH_HFILES} ${_fetch_hfiles_gen}
)
target_compile_definitions(${EXE_NAME} PRIVATE ${_fetch_definitions})

add_executable(
  ${PROJECT_NAME}::${EXE_NAME}
  ALIAS ${EXE_NAME}
)

add_library(
  fetchtool  # special libfetchtool library just for unittests
  STATIC
  EXCLUDE_FROM_ALL
  ${FETCH_CFILES} ${FETCHTOOL_LIBFETCH_CFILES} ${FETCH_HFILES}
)
target_compile_definitions(fetchtool PUBLIC "UNITTESTS" "FETCH_STATICLIB")
target_link_libraries(fetchtool PRIVATE ${FETCH_LIBS})

if(FETCH_HAS_LTO)
  set_target_properties(${EXE_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

if(ENABLE_UNICODE AND MINGW)
  target_link_libraries(${EXE_NAME} "-municode")
endif()

source_group("fetchX source files" FILES ${FETCHX_CFILES})
source_group("fetch source files" FILES ${FETCH_CFILES} ${_fetch_cfiles_gen})
source_group("fetch header files" FILES ${FETCH_HFILES} ${_fetch_hfiles_gen})

include_directories(
  "${PROJECT_BINARY_DIR}/lib"  # for "fetch_config.h"
  "${PROJECT_SOURCE_DIR}/lib"  # for "fetch_setup.h"
  # This is needed as tool_hugehelp.c is generated in the binary dir
  "${PROJECT_SOURCE_DIR}/src"  # for "tool_hugehelp.h"
)

# Build fetch executable
target_link_libraries(${EXE_NAME} ${LIB_SELECTED_FOR_EXE} ${FETCH_LIBS})

################################################################################

install(TARGETS ${EXE_NAME} EXPORT ${TARGETS_EXPORT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
export(TARGETS ${EXE_NAME}
  FILE "${PROJECT_BINARY_DIR}/fetch-target.cmake"
  NAMESPACE ${PROJECT_NAME}::
)
