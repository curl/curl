#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################
# Load man_MANS from shared file
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

function(add_manual_pages _listname)
  foreach(_file IN LISTS ${_listname})
    if(_file STREQUAL "libcurl-symbols.3")
      # Special case, an auto-generated file.
      set(_srcfile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    else()
      set(_srcfile "${CMAKE_CURRENT_SOURCE_DIR}/${_file}")
    endif()

    string(REPLACE ".3" ".html" _htmlfile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    add_custom_command(OUTPUT "${_htmlfile}"
      COMMAND roffit "--mandir=${CMAKE_CURRENT_SOURCE_DIR}" "${_srcfile}" > "${_htmlfile}"
      DEPENDS "${_srcfile}"
      VERBATIM
    )

    string(REPLACE ".3" ".pdf" _pdffile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    string(REPLACE ".3" ".ps" _psfile "${CMAKE_CURRENT_BINARY_DIR}/${_file}")
    # XXX any reason why groff -Tpdf (for gropdf) is not used?
    add_custom_command(OUTPUT "${_pdffile}"
      COMMAND groff -Tps -man "${_srcfile}" > "${_psfile}"
      COMMAND ps2pdf "${_psfile}" "${_pdffile}"
      COMMAND "${CMAKE_COMMAND}" -E remove "${_psfile}"
      DEPENDS "${_srcfile}"
      #BYPRODUCTS "${_psfile}"
      VERBATIM
    )
    # "BYPRODUCTS" for add_custom_command requires CMake 3.2. For now hope that
    # the temporary files are removed (i.e. the command is not interrupted).
  endforeach()
endfunction()

add_custom_command(OUTPUT libcurl-symbols.3
  COMMAND
    "${PERL_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl" <
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions" > libcurl-symbols.3
  DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/symbols-in-versions"
    "${CMAKE_CURRENT_SOURCE_DIR}/mksymbolsmanpage.pl"
  VERBATIM
)

add_manual_pages(man_MANS)

string(REPLACE ".3" ".html" HTMLPAGES "${man_MANS}")
string(REPLACE ".3" ".pdf" PDFPAGES "${man_MANS}")
add_custom_target(html DEPENDS ${HTMLPAGES})
add_custom_target(pdf DEPENDS ${PDFPAGES})

add_subdirectory(opts)
