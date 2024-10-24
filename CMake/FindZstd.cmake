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
# Find the zstd library
#
# Input variables:
#
# - `ZSTD_INCLUDE_DIR`:   The zstd include directory.
# - `ZSTD_LIBRARY`:       Path to `zstd` library.
#
# Result variables:
#
# - `ZSTD_FOUND`:         System has zstd.
# - `ZSTD_INCLUDE_DIRS`:  The zstd include directories.
# - `ZSTD_LIBRARIES`:     The zstd library names.
# - `ZSTD_VERSION`:       Version of zstd.

if(DEFINED Zstd_INCLUDE_DIR AND NOT DEFINED ZSTD_INCLUDE_DIR)
  message(WARNING "Zstd_INCLUDE_DIR is deprecated, use ZSTD_INCLUDE_DIR instead.")
  set(ZSTD_INCLUDE_DIR "${Zstd_INCLUDE_DIR}")
endif()
if(DEFINED Zstd_LIBRARY AND NOT DEFINED ZSTD_LIBRARY)
  message(WARNING "Zstd_LIBRARY is deprecated, use ZSTD_LIBRARY instead.")
  set(ZSTD_LIBRARY "${Zstd_LIBRARY}")
endif()

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_ZSTD "libzstd")
endif()

find_path(ZSTD_INCLUDE_DIR NAMES "zstd.h"
  HINTS
    ${PC_ZSTD_INCLUDEDIR}
    ${PC_ZSTD_INCLUDE_DIRS}
)

find_library(ZSTD_LIBRARY NAMES "zstd"
  HINTS
    ${PC_ZSTD_LIBDIR}
    ${PC_ZSTD_LIBRARY_DIRS}
)

if(PC_ZSTD_VERSION)
  set(ZSTD_VERSION ${PC_ZSTD_VERSION})
elseif(ZSTD_INCLUDE_DIR AND EXISTS "${ZSTD_INCLUDE_DIR}/zstd.h")
  set(_version_regex1 "#[\t ]*define[ \t]+ZSTD_VERSION_MAJOR[ \t]+([0-9]+).*")
  set(_version_regex2 "#[\t ]*define[ \t]+ZSTD_VERSION_MINOR[ \t]+([0-9]+).*")
  set(_version_regex3 "#[\t ]*define[ \t]+ZSTD_VERSION_RELEASE[ \t]+([0-9]+).*")
  file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str1 REGEX "${_version_regex1}")
  file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str2 REGEX "${_version_regex2}")
  file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str3 REGEX "${_version_regex3}")
  string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
  string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
  string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
  set(ZSTD_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
  unset(_version_regex1)
  unset(_version_regex2)
  unset(_version_regex3)
  unset(_version_str1)
  unset(_version_str2)
  unset(_version_str3)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zstd
  REQUIRED_VARS
    ZSTD_INCLUDE_DIR
    ZSTD_LIBRARY
  VERSION_VAR
    ZSTD_VERSION
)

if(ZSTD_FOUND)
  set(ZSTD_INCLUDE_DIRS ${ZSTD_INCLUDE_DIR})
  set(ZSTD_LIBRARIES    ${ZSTD_LIBRARY})
endif()

mark_as_advanced(ZSTD_INCLUDE_DIR ZSTD_LIBRARY)
