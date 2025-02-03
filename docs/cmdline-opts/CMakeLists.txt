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
# are also available at https://curl.se/docs/copyright.html.
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
# Get 'DPAGES' variable
fetch_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT "${FETCH_MANPAGE}" "${FETCH_ASCIIPAGE}"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/managen" mainpage ${DPAGES} > "${FETCH_MANPAGE}"
  COMMAND "${PERL_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/managen" ascii ${DPAGES} > "${FETCH_ASCIIPAGE}"
  DEPENDS
    "${PROJECT_SOURCE_DIR}/scripts/managen"
    ${DPAGES}
  VERBATIM
)

add_custom_target(generate-fetch.1 ALL DEPENDS "${FETCH_MANPAGE}")

if(NOT FETCH_DISABLE_INSTALL)
  install(FILES "${FETCH_MANPAGE}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man1")
endif()
