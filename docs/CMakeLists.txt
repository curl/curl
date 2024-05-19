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

if(BUILD_LIBCURL_DOCS)
  add_subdirectory(libcurl)
endif()
if(ENABLE_CURL_MANUAL AND BUILD_CURL_EXE)
  add_subdirectory(cmdline-opts)
endif()

if(BUILD_MISC_DOCS)
  foreach(_man_misc IN ITEMS "curl-config" "mk-ca-bundle")
    set(_man_target "${CURL_BINARY_DIR}/docs/${_man_misc}.1")
    add_custom_command(OUTPUT "${_man_target}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMAND "${PERL_EXECUTABLE}" ${PROJECT_SOURCE_DIR}/scripts/cd2nroff "${_man_misc}.md" > "${_man_target}"
      DEPENDS "${_man_misc}.md"
      VERBATIM
    )
    add_custom_target("curl-generate-${_man_misc}.1" ALL DEPENDS "${_man_target}")
    if(NOT CURL_DISABLE_INSTALL)
      install(FILES "${_man_target}" DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    endif()
  endforeach()
endif()
