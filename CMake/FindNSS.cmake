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
if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_NSS nss)
endif()
if(NOT PC_NSS_FOUND)
  return()
endif()

set(NSS_LIBRARIES ${PC_NSS_LINK_LIBRARIES})
set(NSS_INCLUDE_DIRS ${PC_NSS_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NSS
    REQUIRED_VARS NSS_LIBRARIES NSS_INCLUDE_DIRS
    VERSION_VAR PC_NSS_VERSION)

mark_as_advanced(NSS_INCLUDE_DIRS NSS_LIBRARIES)
