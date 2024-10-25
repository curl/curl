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
# Find the libuv library
#
# Input variables:
#
# - `LIBUV_INCLUDE_DIR`:   The libuv include directory.
# - `LIBUV_LIBRARY`:       Path to `libuv` library.
#
# Result variables:
#
# - `LIBUV_FOUND`:         System has libuv.
# - `LIBUV_INCLUDE_DIRS`:  The libuv include directories.
# - `LIBUV_LIBRARIES`:     The libuv library names.
# - `LIBUV_LIBRARY_DIRS`:  The libuv library directories.
# - `LIBUV_CFLAGS`:        Required compiler flags.
# - `LIBUV_VERSION`:       Version of libuv.

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBUV_INCLUDE_DIR AND
   NOT DEFINED LIBUV_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBUV "libuv")
endif()

if(LIBUV_FOUND)
  string(REPLACE ";" " " LIBUV_CFLAGS "${LIBUV_CFLAGS}")
  message(STATUS "Found Libuv (via pkg-config): ${LIBUV_INCLUDE_DIRS} (found version \"${LIBUV_VERSION}\")")
else()
  find_path(LIBUV_INCLUDE_DIR NAMES "uv.h")
  find_library(LIBUV_LIBRARY NAMES "uv" "libuv")

  unset(LIBUV_VERSION CACHE)
  if(LIBUV_INCLUDE_DIR AND EXISTS "${LIBUV_INCLUDE_DIR}/uv/version.h")
    set(_version_regex1 "#[\t ]*define[\t ]+UV_VERSION_MAJOR[\t ]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[\t ]+UV_VERSION_MINOR[\t ]+([0-9]+).*")
    set(_version_regex3 "#[\t ]*define[\t ]+UV_VERSION_PATCH[\t ]+([0-9]+).*")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str2 REGEX "${_version_regex2}")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str3 REGEX "${_version_regex3}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
    set(LIBUV_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
    unset(_version_regex1)
    unset(_version_regex2)
    unset(_version_regex3)
    unset(_version_str1)
    unset(_version_str2)
    unset(_version_str3)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libuv
    REQUIRED_VARS
      LIBUV_INCLUDE_DIR
      LIBUV_LIBRARY
    VERSION_VAR
      LIBUV_VERSION
  )

  if(LIBUV_FOUND)
    set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
    set(LIBUV_LIBRARIES    ${LIBUV_LIBRARY})
  endif()

  mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)
endif()
