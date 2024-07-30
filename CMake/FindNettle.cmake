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
# - Try to find the nettle library
# Once done this will define
#
# NETTLE_FOUND - system has nettle
# NETTLE_INCLUDE_DIRS - nettle include directories
# NETTLE_LIBRARIES - nettle library names

if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_check_modules(NETTLE "nettle")
endif()

if(NETTLE_FOUND)
  set(NETTLE_LIBRARIES ${NETTLE_LINK_LIBRARIES})
else()
  find_path(NETTLE_INCLUDE_DIR NAMES "nettle/sha2.h")
  find_library(NETTLE_LIBRARY NAMES "nettle")

  if(NETTLE_INCLUDE_DIR)
    if(EXISTS "${NETTLE_INCLUDE_DIR}/nettle/version.h")
      set(_version_regex_major "^#define[ \t]+NETTLE_VERSION_MAJOR[ \t]+([0-9]+).*")
      set(_version_regex_minor "^#define[ \t]+NETTLE_VERSION_MINOR[ \t]+([0-9]+).*")
      file(STRINGS "${NETTLE_INCLUDE_DIR}/nettle/version.h"
        _version_major REGEX "${_version_regex_major}")
      file(STRINGS "${NETTLE_INCLUDE_DIR}/nettle/version.h"
        _version_minor REGEX "${_version_regex_minor}")
      string(REGEX REPLACE "${_version_regex_major}" "\\1" _version_major "${_version_major}")
      string(REGEX REPLACE "${_version_regex_minor}" "\\1" _version_minor "${_version_minor}")
      unset(_version_regex_major)
      unset(_version_regex_minor)
      set(NETTLE_VERSION "${_version_major}.${_version_minor}")
      unset(_version_major)
      unset(_version_minor)
    else()
      set(NETTLE_VERSION "0.0")
    endif()
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args("nettle"
    REQUIRED_VARS
      NETTLE_INCLUDE_DIR
      NETTLE_LIBRARY
    VERSION_VAR NETTLE_VERSION)

  if(NETTLE_FOUND)
    set(NETTLE_INCLUDE_DIRS ${NETTLE_INCLUDE_DIR})
    set(NETTLE_LIBRARIES    ${NETTLE_LIBRARY})
  endif()

  mark_as_advanced(NETTLE_INCLUDE_DIR NETTLE_LIBRARY)
endif()
