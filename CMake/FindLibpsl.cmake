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
# Find the libpsl library
#
# Input variables:
#
# - `LIBPSL_INCLUDE_DIR`:   The libpsl include directory.
# - `LIBPSL_LIBRARY`:       Path to `libpsl` library.
#
# Result variables:
#
# - `LIBPSL_FOUND`:         System has libpsl.
# - `LIBPSL_INCLUDE_DIRS`:  The libpsl include directories.
# - `LIBPSL_LIBRARIES`:     The libpsl library names.
# - `LIBPSL_VERSION`:       Version of libpsl.

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_LIBPSL "libpsl")
endif()

find_path(LIBPSL_INCLUDE_DIR NAMES "libpsl.h"
  HINTS
    ${PC_LIBPSL_INCLUDEDIR}
    ${PC_LIBPSL_INCLUDE_DIRS}
)

find_library(LIBPSL_LIBRARY NAMES "psl" "libpsl"
  HINTS
    ${PC_LIBPSL_LIBDIR}
    ${PC_LIBPSL_LIBRARY_DIRS}
)

if(PC_LIBPSL_VERSION)
  set(LIBPSL_VERSION ${PC_LIBPSL_VERSION})
elseif(LIBPSL_INCLUDE_DIR AND EXISTS "${LIBPSL_INCLUDE_DIR}/libpsl.h")
  set(_version_regex "#[\t ]*define[\t ]+PSL_VERSION[\t ]+\"([^\"]*)\"")
  file(STRINGS "${LIBPSL_INCLUDE_DIR}/libpsl.h" _version_str REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
  set(LIBPSL_VERSION "${_version_str}")
  unset(_version_regex)
  unset(_version_str)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libpsl
  REQUIRED_VARS
    LIBPSL_INCLUDE_DIR
    LIBPSL_LIBRARY
  VERSION_VAR
    LIBPSL_VERSION
)

if(LIBPSL_FOUND)
  set(LIBPSL_INCLUDE_DIRS ${LIBPSL_INCLUDE_DIR})
  set(LIBPSL_LIBRARIES    ${LIBPSL_LIBRARY})
endif()

mark_as_advanced(LIBPSL_INCLUDE_DIR LIBPSL_LIBRARY)
