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
# Find the c-ares library
#
# Input variables:
#
# CARES_INCLUDE_DIR   The c-ares include directory
# CARES_LIBRARY       Path to c-ares library
#
# Result variables:
#
# CARES_FOUND         System has c-ares
# CARES_INCLUDE_DIRS  The c-ares include directories
# CARES_LIBRARIES     The c-ares library names
# CARES_VERSION       Version of c-ares

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_CARES "libcares")
endif()

find_path(CARES_INCLUDE_DIR NAMES "ares.h"
  HINTS
    ${PC_CARES_INCLUDEDIR}
    ${PC_CARES_INCLUDE_DIRS}
)

find_library(CARES_LIBRARY NAMES ${CARES_NAMES} "cares"
  HINTS
    ${PC_CARES_LIBDIR}
    ${PC_CARES_LIBRARY_DIRS}
)

if(PC_CARES_VERSION)
  set(CARES_VERSION ${PC_CARES_VERSION})
elseif(CARES_INCLUDE_DIR AND EXISTS "${CARES_INCLUDE_DIR}/ares_version.h")
  set(_version_regex "#[\t ]*define[\t ]+ARES_VERSION_STR[\t ]+\"([^\"]*)\"")
  file(STRINGS "${CARES_INCLUDE_DIR}/ares_version.h" _version_str REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
  set(CARES_VERSION "${_version_str}")
  unset(_version_regex)
  unset(_version_str)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cares
  REQUIRED_VARS
    CARES_INCLUDE_DIR
    CARES_LIBRARY
  VERSION_VAR
    CARES_VERSION
)

if(CARES_FOUND)
  set(CARES_INCLUDE_DIRS ${CARES_INCLUDE_DIR})
  set(CARES_LIBRARIES    ${CARES_LIBRARY})
endif()

mark_as_advanced(CARES_INCLUDE_DIR CARES_LIBRARY)
