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
# Get CERTCONFIG_CA, CERTCONFIGS, GENERATEDCERTS, SRPFILES variables
curl_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_command(OUTPUT ${GENERATEDCERTS}
  COMMAND "${PERL_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/genserv.pl" "test" ${CERTCONFIGS}
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/genserv.pl" ${CERTCONFIG_CA} ${CERTCONFIGS}
  VERBATIM
)
add_custom_target(build-certs DEPENDS ${GENERATEDCERTS})

option(_CURL_SKIP_BUILD_CERTS "Skip building certs with testdeps" OFF)  # Internal option to increase perf for build tests
if(NOT _CURL_SKIP_BUILD_CERTS)
  add_dependencies(testdeps build-certs)
endif()

add_custom_target(clean-certs
  COMMAND ${CMAKE_COMMAND} -E remove ${GENERATEDCERTS}
    "test-*.csr"
    "test-*.der"
    "test-*.keyenc"
    "test-ca.cnt*"
    "test-ca.db*"
    "test-ca.raw*"
    "test-ca.srl"
)
