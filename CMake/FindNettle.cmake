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
# Find the nettle library
#
# Input variables:
#
# - `NETTLE_INCLUDE_DIR`:   The nettle include directory.
# - `NETTLE_LIBRARY`:       Path to `nettle` library.
#
# Result variables:
#
# - `NETTLE_FOUND`:         System has nettle.
# - `NETTLE_INCLUDE_DIRS`:  The nettle include directories.
# - `NETTLE_LIBRARIES`:     The nettle library names.
# - `NETTLE_LIBRARY_DIRS`:  The nettle library directories.
# - `NETTLE_CFLAGS`:        Required compiler flags.
# - `NETTLE_VERSION`:       Version of nettle.

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED NETTLE_INCLUDE_DIR AND
   NOT DEFINED NETTLE_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(NETTLE "nettle")
endif()

if(NETTLE_FOUND)
  string(REPLACE ";" " " NETTLE_CFLAGS "${NETTLE_CFLAGS}")
  message(STATUS "Found Nettle (via pkg-config): ${NETTLE_INCLUDE_DIRS} (found version \"${NETTLE_VERSION}\")")
else()
  find_path(NETTLE_INCLUDE_DIR NAMES "nettle/sha2.h")
  find_library(NETTLE_LIBRARY NAMES "nettle")

  unset(NETTLE_VERSION CACHE)
  if(NETTLE_INCLUDE_DIR AND EXISTS "${NETTLE_INCLUDE_DIR}/nettle/version.h")
    set(_version_regex1 "#[\t ]*define[ \t]+NETTLE_VERSION_MAJOR[ \t]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[ \t]+NETTLE_VERSION_MINOR[ \t]+([0-9]+).*")
    file(STRINGS "${NETTLE_INCLUDE_DIR}/nettle/version.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${NETTLE_INCLUDE_DIR}/nettle/version.h" _version_str2 REGEX "${_version_regex2}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    set(NETTLE_VERSION "${_version_str1}.${_version_str2}")
    unset(_version_regex1)
    unset(_version_regex2)
    unset(_version_str1)
    unset(_version_str2)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Nettle
    REQUIRED_VARS
      NETTLE_INCLUDE_DIR
      NETTLE_LIBRARY
    VERSION_VAR
      NETTLE_VERSION
  )

  if(NETTLE_FOUND)
    set(NETTLE_INCLUDE_DIRS ${NETTLE_INCLUDE_DIR})
    set(NETTLE_LIBRARIES    ${NETTLE_LIBRARY})
  endif()

  mark_as_advanced(NETTLE_INCLUDE_DIR NETTLE_LIBRARY)
endif()
