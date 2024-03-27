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
set(MANPAGE "${CURL_BINARY_DIR}/docs/cmdline-opts/curl.1")
set(ASCIIPAGE "${CURL_BINARY_DIR}/docs/cmdline-opts/curl.txt")

# Load DPAGES and OTHERPAGES from shared file
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT "${MANPAGE}"
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND "${PERL_EXECUTABLE}" ${PROJECT_SOURCE_DIR}/scripts/managen mainpage ${DPAGES} > "${MANPAGE}"
  COMMAND "${PERL_EXECUTABLE}" ${PROJECT_SOURCE_DIR}/scripts/managen ascii ${DPAGES} > "${ASCIIPAGE}"
  VERBATIM
)
add_custom_target(generate-curl.1 ALL DEPENDS "${MANPAGE}")
if(NOT CURL_DISABLE_INSTALL)
  install(FILES "${MANPAGE}" DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()
