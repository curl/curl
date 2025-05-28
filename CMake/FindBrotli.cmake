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
# - `BROTLI_INCLUDE_DIR`:    The brotli include directory.
# - `BROTLICOMMON_LIBRARY`:  Path to `brotlicommon` library.
# - `BROTLIDEC_LIBRARY`:     Path to `brotlidec` library.
#
# Result variables:
#
# - `BROTLI_FOUND`:          System has brotli.
# - `BROTLI_INCLUDE_DIRS`:   The brotli include directories.
# - `BROTLI_LIBRARIES`:      The brotli library names.
# - `BROTLI_LIBRARY_DIRS`:   The brotli library directories.
# - `BROTLI_PC_REQUIRES`:    The brotli pkg-config packages.
# - `BROTLI_CFLAGS`:         Required compiler flags.
# - `BROTLI_VERSION`:        Version of brotli.

set(BROTLI_PC_REQUIRES "libbrotlidec" "libbrotlicommon")  # order is significant: brotlidec then brotlicommon

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED BROTLI_INCLUDE_DIR AND
   NOT DEFINED BROTLICOMMON_LIBRARY AND
   NOT DEFINED BROTLIDEC_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(BROTLI ${BROTLI_PC_REQUIRES})
endif()

if(BROTLI_FOUND)
  set(Brotli_FOUND TRUE)
  set(BROTLI_VERSION "${BROTLI_libbrotlicommon_VERSION}")
  string(REPLACE ";" " " BROTLI_CFLAGS "${BROTLI_CFLAGS}")
  message(STATUS "Found Brotli (via pkg-config): ${BROTLI_INCLUDE_DIRS} (found version \"${BROTLI_VERSION}\")")
else()
  find_path(BROTLI_INCLUDE_DIR "brotli/decode.h")
  find_library(BROTLICOMMON_LIBRARY NAMES "brotlicommon")
  find_library(BROTLIDEC_LIBRARY NAMES "brotlidec")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Brotli
    REQUIRED_VARS
      BROTLI_INCLUDE_DIR
      BROTLIDEC_LIBRARY
      BROTLICOMMON_LIBRARY
  )

  if(BROTLI_FOUND)
    set(BROTLI_INCLUDE_DIRS ${BROTLI_INCLUDE_DIR})
    set(BROTLI_LIBRARIES ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})
  endif()

  mark_as_advanced(BROTLI_INCLUDE_DIR BROTLIDEC_LIBRARY BROTLICOMMON_LIBRARY)
endif()
