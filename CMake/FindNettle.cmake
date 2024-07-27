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
# NETTLE_FOUND - system has the nettle library
# NETTLE_INCLUDE_DIR - the nettle include directory
# NETTLE_LIBRARY - the nettle library name

if(UNIX)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_NETTLE QUIET "nettle")
  endif()
endif()

find_path(NETTLE_INCLUDE_DIR
  NAMES "nettle/sha2.h"
  HINTS ${PC_NETTLE_INCLUDE_DIRS}
)

find_library(NETTLE_LIBRARY
  NAMES "nettle"
  HINTS ${PC_NETTLE_LIBRARY_DIRS}
)

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
  elseif(PC_NETTLE_VERSION)
    set(NETTLE_VERSION ${PC_NETTLE_VERSION})
  else()
    set(NETTLE_VERSION "0.0")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(nettle
  REQUIRED_VARS NETTLE_LIBRARY NETTLE_INCLUDE_DIR
  VERSION_VAR NETTLE_VERSION
)

if(NETTLE_FOUND)
  set(NETTLE_LIBRARIES    ${NETTLE_LIBRARY})
  set(NETTLE_INCLUDE_DIRS ${NETTLE_INCLUDE_DIR})
endif()

mark_as_advanced(NETTLE_INCLUDE_DIR NETTLE_LIBRARY)
