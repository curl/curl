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
# Get 'man_MANS' variable
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_manual_pages(man_MANS)
add_custom_target(curl-opts-man DEPENDS ${man_MANS})
add_dependencies(curl-man curl-opts-man)
if(NOT CURL_DISABLE_INSTALL)
  unset(_src)
  foreach(_f IN LISTS man_MANS)
    list(APPEND _src "${CMAKE_CURRENT_BINARY_DIR}/${_f}")
  endforeach()
  install(FILES ${_src} DESTINATION "${CMAKE_INSTALL_MANDIR}/man3")
endif()
