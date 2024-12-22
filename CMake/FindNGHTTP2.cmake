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
# Find the nghttp2 library
#
# Input variables:
#
# - `NGHTTP2_INCLUDE_DIR`:   The nghttp2 include directory.
# - `NGHTTP2_LIBRARY`:       Path to `nghttp2` library.
#
# Result variables:
#
# - `NGHTTP2_FOUND`:         System has nghttp2.
# - `NGHTTP2_INCLUDE_DIRS`:  The nghttp2 include directories.
# - `NGHTTP2_LIBRARIES`:     The nghttp2 library names.
# - `NGHTTP2_LIBRARY_DIRS`:  The nghttp2 library directories.
# - `NGHTTP2_PC_REQUIRES`:   The nghttp2 pkg-config packages.
# - `NGHTTP2_CFLAGS`:        Required compiler flags.
# - `NGHTTP2_VERSION`:       Version of nghttp2.

set(NGHTTP2_PC_REQUIRES "libnghttp2")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED NGHTTP2_INCLUDE_DIR AND
   NOT DEFINED NGHTTP2_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(NGHTTP2 ${NGHTTP2_PC_REQUIRES})
endif()

if(NGHTTP2_FOUND)
  string(REPLACE ";" " " NGHTTP2_CFLAGS "${NGHTTP2_CFLAGS}")
  message(STATUS "Found NGHTTP2 (via pkg-config): ${NGHTTP2_INCLUDE_DIRS} (found version \"${NGHTTP2_VERSION}\")")
else()
  find_path(NGHTTP2_INCLUDE_DIR NAMES "nghttp2/nghttp2.h")
  find_library(NGHTTP2_LIBRARY NAMES "nghttp2" "nghttp2_static")

  unset(NGHTTP2_VERSION CACHE)
  if(NGHTTP2_INCLUDE_DIR AND EXISTS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h")
    set(_version_regex "#[\t ]*define[\t ]+NGHTTP2_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(NGHTTP2_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(NGHTTP2
    REQUIRED_VARS
      NGHTTP2_INCLUDE_DIR
      NGHTTP2_LIBRARY
    VERSION_VAR
      NGHTTP2_VERSION
  )

  if(NGHTTP2_FOUND)
    set(NGHTTP2_INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIR})
    set(NGHTTP2_LIBRARIES    ${NGHTTP2_LIBRARY})
  endif()

  mark_as_advanced(NGHTTP2_INCLUDE_DIR NGHTTP2_LIBRARY)
endif()
