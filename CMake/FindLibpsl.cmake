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
# - `LIBPSL_INCLUDE_DIR`:   Absolute path to libpsl include directory.
# - `LIBPSL_LIBRARY`:       Absolute path to `libpsl` library.
#
# Result variables:
#
# - `LIBPSL_FOUND`:         System has libpsl.
# - `LIBPSL_INCLUDE_DIRS`:  The libpsl include directories.
# - `LIBPSL_LIBRARIES`:     The libpsl library names.
# - `LIBPSL_LIBRARY_DIRS`:  The libpsl library directories.
# - `LIBPSL_PC_REQUIRES`:   The libpsl pkg-config packages.
# - `LIBPSL_CFLAGS`:        Required compiler flags.
# - `LIBPSL_VERSION`:       Version of libpsl.

set(LIBPSL_PC_REQUIRES "libpsl")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBPSL_INCLUDE_DIR AND
   NOT DEFINED LIBPSL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBPSL ${LIBPSL_PC_REQUIRES})
endif()

if(LIBPSL_FOUND AND LIBPSL_INCLUDE_DIRS)
  set(Libpsl_FOUND TRUE)
  string(REPLACE ";" " " LIBPSL_CFLAGS "${LIBPSL_CFLAGS}")
  message(STATUS "Found Libpsl (via pkg-config): ${LIBPSL_INCLUDE_DIRS} (found version \"${LIBPSL_VERSION}\")")
else()
  find_path(LIBPSL_INCLUDE_DIR NAMES "libpsl.h")
  find_library(LIBPSL_LIBRARY NAMES "psl" "libpsl")

  unset(LIBPSL_VERSION CACHE)
  if(LIBPSL_INCLUDE_DIR AND EXISTS "${LIBPSL_INCLUDE_DIR}/libpsl.h")
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
endif()
