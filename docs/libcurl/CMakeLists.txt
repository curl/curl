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
# Load man_MANS from shared file
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

function(add_manual_pages _listname)
  unset(_rofffiles)
  unset(_mdfiles)
  foreach(_file IN LISTS ${_listname})
    list(APPEND _rofffiles "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    if(_file STREQUAL "libcurl-symbols.3")
      # Special case, an auto-generated file.
      string(REPLACE ".3" ".md" _mdfile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    else()
      string(REPLACE ".3" ".md" _mdfile "${_file}")
    endif()
    list(APPEND _mdfiles "${_mdfile}")
  endforeach()

  add_custom_command(OUTPUT ${_rofffiles}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMAND ${PROJECT_SOURCE_DIR}/scripts/cd2nroff -k -d "${CMAKE_CURRENT_BINARY_DIR}" ${_mdfiles}
    DEPENDS ${_mdfiles}
    VERBATIM
  )

endfunction()

add_custom_command(OUTPUT libcurl-symbols.md
  COMMAND
    "${PERL_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl" <
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions" > libcurl-symbols.md
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions"
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl"
  VERBATIM
)

add_manual_pages(man_MANS)
add_custom_target(man ALL DEPENDS ${man_MANS})
if(NOT CURL_DISABLE_INSTALL)
  install(FILES "$<LIST:TRANSFORM,${man_MANS},PREPEND,${CMAKE_CURRENT_BINARY_DIR}/>"
          DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
endif()

add_subdirectory(opts)
