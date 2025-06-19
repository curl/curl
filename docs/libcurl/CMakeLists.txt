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
# Get man_MANS variable
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

# Generate man pages
function(curl_add_manual_pages _listname)
  # Maximum number of files per command to stay within shell/OS limits
  if(CMAKE_HOST_UNIX)
    set(_files_per_batch 10000)
  else()  # e.g. Windows with cmd.exe and other obsolete/unidentified shells
    set(_files_per_batch 200)
  endif()
  set(_file_count 0)
  set(_rofffiles "")
  set(_mdfiles "")
  set(_eol "_EOL_")
  foreach(_file IN LISTS ${_listname} _eol)
    math(EXPR _file_count "${_file_count} + 1")
    if(_file_count GREATER_EQUAL _files_per_batch OR _file STREQUAL "_EOL_")
      add_custom_command(OUTPUT ${_rofffiles}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/cd2nroff" -k -d "${CMAKE_CURRENT_BINARY_DIR}" ${_mdfiles}
        DEPENDS "${PROJECT_SOURCE_DIR}/scripts/cd2nroff" ${_mdfiles}
        VERBATIM
      )
      set(_file_count 0)
      set(_rofffiles "")
      set(_mdfiles "")
    endif()

    list(APPEND _rofffiles "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    if(_file STREQUAL "libcurl-symbols.3")
      # Special case, an auto-generated file.
      string(REPLACE ".3" ".md" _mdfile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    else()
      string(REPLACE ".3" ".md" _mdfile "${_file}")
    endif()
    list(APPEND _mdfiles "${_mdfile}")
  endforeach()
  unset(_rofffiles)
  unset(_mdfiles)
endfunction()

add_custom_command(OUTPUT "libcurl-symbols.md"
  COMMAND
    "${PERL_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl" <
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions" > "libcurl-symbols.md"
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl"
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions"
  VERBATIM
)

curl_add_manual_pages(man_MANS)
add_custom_target(curl-man ALL DEPENDS ${man_MANS})
if(NOT CURL_DISABLE_INSTALL)
  set(_src "")
  foreach(_file IN LISTS man_MANS)
    list(APPEND _src "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
  endforeach()
  install(FILES ${_src} DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
  unset(_src)
endif()

add_subdirectory(opts)
