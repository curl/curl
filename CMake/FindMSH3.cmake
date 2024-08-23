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
# Find the msh3 library
#
# Input variables:
#
# MSH3_INCLUDE_DIR   The msh3 include directory
# MSH3_LIBRARY       Path to msh3 library
#
# Result variables:
#
# MSH3_FOUND         System has msh3
# MSH3_INCLUDE_DIRS  The msh3 include directories
# MSH3_LIBRARIES     The msh3 library names
# MSH3_VERSION       Version of msh3

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_MSH3 "libmsh3")
endif()

find_path(MSH3_INCLUDE_DIR NAMES "msh3.h"
  HINTS
    ${PC_MSH3_INCLUDEDIR}
    ${PC_MSH3_INCLUDE_DIRS}
)

find_library(MSH3_LIBRARY NAMES "msh3"
  HINTS
    ${PC_MSH3_LIBDIR}
    ${PC_MSH3_LIBRARY_DIRS}
)

if(PC_MSH3_VERSION)
  set(MSH3_VERSION ${PC_MSH3_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MSH3
  REQUIRED_VARS
    MSH3_INCLUDE_DIR
    MSH3_LIBRARY
  VERSION_VAR
    MSH3_VERSION
)

if(MSH3_FOUND)
  set(MSH3_INCLUDE_DIRS ${MSH3_INCLUDE_DIR})
  set(MSH3_LIBRARIES    ${MSH3_LIBRARY})
endif()

mark_as_advanced(MSH3_INCLUDE_DIR MSH3_LIBRARY)
