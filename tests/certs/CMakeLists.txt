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
# Get 'CERTCONFIGS', 'GENERATEDCERTS', 'SRPFILES' variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

find_program(SH_EXECUTABLE "sh")
mark_as_advanced(SH_EXECUTABLE)
if(SH_EXECUTABLE)
  add_custom_target(build-certs
    DEPENDS ${CERTCONFIGS}
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test"
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test test-localhost"
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test test-localhost.nn"
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test test-localhost0h"
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test test-localhost-san-first"
    COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/scripts/genserv.sh test test-localhost-san-last"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    VERBATIM USES_TERMINAL
  )
endif()

add_custom_target(clean-certs
  COMMAND ${CMAKE_COMMAND} -E remove ${GENERATEDCERTS}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
