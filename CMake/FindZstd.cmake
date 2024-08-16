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
# Result Variables:
#
# Zstd_FOUND         System has zstd
# Zstd_INCLUDE_DIRS  The zstd include directories
# Zstd_LIBRARIES     The zstd library names
# Zstd_VERSION       Version of zstd

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_Zstd "libzstd")
endif()

find_path(Zstd_INCLUDE_DIR "zstd.h"
  HINTS
    ${PC_Zstd_INCLUDEDIR}
    ${PC_Zstd_INCLUDE_DIRS}
)

find_library(Zstd_LIBRARY NAMES "zstd"
  HINTS
    ${PC_Zstd_LIBDIR}
    ${PC_Zstd_LIBRARY_DIRS}
)

if(PC_Zstd_VERSION)
  set(Zstd_VERSION ${PC_Zstd_VERSION})
elseif(Zstd_INCLUDE_DIR AND EXISTS "${Zstd_INCLUDE_DIR}/zstd.h")
  set(_version_regex1 "#[\t ]*define[ \t]+ZSTD_VERSION_MAJOR[ \t]+([0-9]+).*")
  set(_version_regex2 "#[\t ]*define[ \t]+ZSTD_VERSION_MINOR[ \t]+([0-9]+).*")
  set(_version_regex3 "#[\t ]*define[ \t]+ZSTD_VERSION_RELEASE[ \t]+([0-9]+).*")
  file(STRINGS "${Zstd_INCLUDE_DIR}/zstd.h" _version_str1 REGEX "${_version_regex1}")
  file(STRINGS "${Zstd_INCLUDE_DIR}/zstd.h" _version_str2 REGEX "${_version_regex2}")
  file(STRINGS "${Zstd_INCLUDE_DIR}/zstd.h" _version_str3 REGEX "${_version_regex3}")
  string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
  string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
  string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
  set(Zstd_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
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
    Zstd_INCLUDE_DIR
    Zstd_LIBRARY
  VERSION_VAR
    Zstd_VERSION
)

if(Zstd_FOUND)
  set(Zstd_INCLUDE_DIRS ${Zstd_INCLUDE_DIR})
  set(Zstd_LIBRARIES    ${Zstd_LIBRARY})
endif()

mark_as_advanced(Zstd_INCLUDE_DIR Zstd_LIBRARY)
