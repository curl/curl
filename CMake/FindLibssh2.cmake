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
# Find the libssh2 library
#
# Input variables:
#
# - `LIBSSH2_INCLUDE_DIR`:   The libssh2 include directory.
# - `LIBSSH2_LIBRARY`:       Path to `libssh2` library.
#
# Result variables:
#
# - `LIBSSH2_FOUND`:         System has libssh2.
# - `LIBSSH2_INCLUDE_DIRS`:  The libssh2 include directories.
# - `LIBSSH2_LIBRARIES`:     The libssh2 library names.
# - `LIBSSH2_VERSION`:       Version of libssh2.

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_LIBSSH2 "libssh2")
endif()

find_path(LIBSSH2_INCLUDE_DIR NAMES "libssh2.h"
  HINTS
    ${PC_LIBSSH2_INCLUDEDIR}
    ${PC_LIBSSH2_INCLUDE_DIRS}
)

find_library(LIBSSH2_LIBRARY NAMES "ssh2" "libssh2"
  HINTS
    ${PC_LIBSSH2_LIBDIR}
    ${PC_LIBSSH2_LIBRARY_DIRS}
)

if(PC_LIBSSH2_VERSION)
  set(LIBSSH2_VERSION ${PC_LIBSSH2_VERSION})
elseif(LIBSSH2_INCLUDE_DIR AND EXISTS "${LIBSSH2_INCLUDE_DIR}/libssh2.h")
  set(_version_regex "#[\t ]*define[\t ]+LIBSSH2_VERSION[\t ]+\"([^\"]*)\"")
  file(STRINGS "${LIBSSH2_INCLUDE_DIR}/libssh2.h" _version_str REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
  set(LIBSSH2_VERSION "${_version_str}")
  unset(_version_regex)
  unset(_version_str)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libssh2
  REQUIRED_VARS
    LIBSSH2_INCLUDE_DIR
    LIBSSH2_LIBRARY
  VERSION_VAR
    LIBSSH2_VERSION
)

if(LIBSSH2_FOUND)
  set(LIBSSH2_INCLUDE_DIRS ${LIBSSH2_INCLUDE_DIR})
  set(LIBSSH2_LIBRARIES    ${LIBSSH2_LIBRARY})
endif()

mark_as_advanced(LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY)
