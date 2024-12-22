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
# Find the libgsasl library
#
# Input variables:
#
# - `LIBGSASL_INCLUDE_DIR`:   The libgsasl include directory.
# - `LIBGSASL_LIBRARY`:       Path to `libgsasl` library.
#
# Result variables:
#
# - `LIBGSASL_FOUND`:         System has libgsasl.
# - `LIBGSASL_INCLUDE_DIRS`:  The libgsasl include directories.
# - `LIBGSASL_LIBRARIES`:     The libgsasl library names.
# - `LIBGSASL_LIBRARY_DIRS`:  The libgsasl library directories.
# - `LIBGSASL_PC_REQUIRES`:   The libgsasl pkg-config packages.
# - `LIBGSASL_CFLAGS`:        Required compiler flags.
# - `LIBGSASL_VERSION`:       Version of libgsasl.

set(LIBGSASL_PC_REQUIRES "libgsasl")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBGSASL_INCLUDE_DIR AND
   NOT DEFINED LIBGSASL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBGSASL ${LIBGSASL_PC_REQUIRES})
endif()

if(LIBGSASL_FOUND)
  string(REPLACE ";" " " LIBGSASL_CFLAGS "${LIBGSASL_CFLAGS}")
  message(STATUS "Found Libgsasl (via pkg-config): ${LIBGSASL_INCLUDE_DIRS} (found version \"${LIBGSASL_VERSION}\")")
else()
  find_path(LIBGSASL_INCLUDE_DIR NAMES "gsasl.h")
  find_library(LIBGSASL_LIBRARY NAMES "gsasl" "libgsasl")

  unset(LIBGSASL_VERSION CACHE)
  if(LIBGSASL_INCLUDE_DIR AND EXISTS "${LIBGSASL_INCLUDE_DIR}/gsasl-version.h")
    set(_version_regex "#[\t ]*define[\t ]+GSASL_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${LIBGSASL_INCLUDE_DIR}/gsasl-version.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(LIBGSASL_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Libgsasl
    REQUIRED_VARS
      LIBGSASL_INCLUDE_DIR
      LIBGSASL_LIBRARY
    VERSION_VAR
      LIBGSASL_VERSION
  )

  if(LIBGSASL_FOUND)
    set(LIBGSASL_INCLUDE_DIRS ${LIBGSASL_INCLUDE_DIR})
    set(LIBGSASL_LIBRARIES    ${LIBGSASL_LIBRARY})
  endif()

  mark_as_advanced(LIBGSASL_INCLUDE_DIR LIBGSASL_LIBRARY)
endif()
