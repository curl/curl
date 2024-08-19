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
# Find the quiche library
#
# Input variables:
#
# QUICHE_INCLUDE_DIR   The quiche include directory
# QUICHE_LIBRARY       Path to quiche library
#
# Result variables:
#
# QUICHE_FOUND         System has quiche
# QUICHE_INCLUDE_DIRS  The quiche include directories
# QUICHE_LIBRARIES     The quiche library names
# QUICHE_VERSION       Version of quiche

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_QUICHE "quiche")
endif()

find_path(QUICHE_INCLUDE_DIR NAMES "quiche.h"
  HINTS
    ${PC_QUICHE_INCLUDEDIR}
    ${PC_QUICHE_INCLUDE_DIRS}
)

find_library(QUICHE_LIBRARY NAMES "quiche"
  HINTS
    ${PC_QUICHE_LIBDIR}
    ${PC_QUICHE_LIBRARY_DIRS}
)

if(PC_QUICHE_VERSION)
  set(QUICHE_VERSION ${PC_QUICHE_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Quiche
  REQUIRED_VARS
    QUICHE_INCLUDE_DIR
    QUICHE_LIBRARY
  VERSION_VAR
    QUICHE_VERSION
)

if(QUICHE_FOUND)
  set(QUICHE_INCLUDE_DIRS ${QUICHE_INCLUDE_DIR})
  set(QUICHE_LIBRARIES    ${QUICHE_LIBRARY})
endif()

mark_as_advanced(QUICHE_INCLUDE_DIR QUICHE_LIBRARY)
