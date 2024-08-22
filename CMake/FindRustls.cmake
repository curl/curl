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
# Find the rustls library
#
# Input variables:
#
# RUSTLS_INCLUDE_DIR   The rustls include directory
# RUSTLS_LIBRARY       Path to rustls library
#
# Result variables:
#
# RUSTLS_FOUND         System has rustls
# RUSTLS_INCLUDE_DIRS  The rustls include directories
# RUSTLS_LIBRARIES     The rustls library names
# RUSTLS_VERSION       Version of rustls

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_RUSTLS "rustls")
endif()

find_path(RUSTLS_INCLUDE_DIR NAMES "rustls.h"
  HINTS
    ${PC_RUSTLS_INCLUDEDIR}
    ${PC_RUSTLS_INCLUDE_DIRS}
)

find_library(RUSTLS_LIBRARY NAMES "rustls"
  HINTS
    ${PC_RUSTLS_LIBDIR}
    ${PC_RUSTLS_LIBRARY_DIRS}
)

if(PC_RUSTLS_VERSION)
  set(RUSTLS_VERSION ${PC_RUSTLS_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Rustls
  REQUIRED_VARS
    RUSTLS_INCLUDE_DIR
    RUSTLS_LIBRARY
  VERSION_VAR
    RUSTLS_VERSION
)

if(RUSTLS_FOUND)
  set(RUSTLS_INCLUDE_DIRS ${RUSTLS_INCLUDE_DIR})
  set(RUSTLS_LIBRARIES    ${RUSTLS_LIBRARY})
endif()

mark_as_advanced(RUSTLS_INCLUDE_DIR RUSTLS_LIBRARY)
