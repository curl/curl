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
# Find the brotli library
#
# Input variables:
#
# BROTLI_INCLUDE_DIR   The brotli include directory
# BROTLICOMMON_LIBRARY Path to brotlicommon library
# BROTLIDEC_LIBRARY    Path to brotlidec library
#
# Result variables:
#
# BROTLI_FOUND         System has brotli
# BROTLI_INCLUDE_DIRS  The brotli include directories
# BROTLI_LIBRARIES     The brotli library names
# BROTLI_VERSION       Version of brotli

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_BROTLI "libbrotlidec")
endif()

find_path(BROTLI_INCLUDE_DIR "brotli/decode.h"
  HINTS
    ${PC_BROTLI_INCLUDEDIR}
    ${PC_BROTLI_INCLUDE_DIRS}
)

find_library(BROTLICOMMON_LIBRARY NAMES "brotlicommon"
  HINTS
    ${PC_BROTLI_LIBDIR}
    ${PC_BROTLI_LIBRARY_DIRS}
)
find_library(BROTLIDEC_LIBRARY NAMES "brotlidec"
  HINTS
    ${PC_BROTLI_LIBDIR}
    ${PC_BROTLI_LIBRARY_DIRS}
)

if(PC_BROTLI_VERSION)
  set(BROTLI_VERSION ${PC_BROTLI_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Brotli
  REQUIRED_VARS
    BROTLI_INCLUDE_DIR
    BROTLIDEC_LIBRARY
    BROTLICOMMON_LIBRARY
  VERSION_VAR
    BROTLI_VERSION
)

if(BROTLI_FOUND)
  set(BROTLI_INCLUDE_DIRS ${BROTLI_INCLUDE_DIR})
  set(BROTLI_LIBRARIES ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})
endif()

mark_as_advanced(BROTLI_INCLUDE_DIR BROTLIDEC_LIBRARY BROTLICOMMON_LIBRARY)
