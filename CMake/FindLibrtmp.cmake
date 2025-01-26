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
# Find the librtmp library
#
# Input variables:
#
# - `LIBRTMP_INCLUDE_DIR`:   The librtmp include directory.
# - `LIBRTMP_LIBRARY`:       Path to `librtmp` library.
#
# Result variables:
#
# - `LIBRTMP_FOUND`:         System has librtmp.
# - `LIBRTMP_INCLUDE_DIRS`:  The librtmp include directories.
# - `LIBRTMP_LIBRARIES`:     The librtmp library names.
# - `LIBRTMP_LIBRARY_DIRS`:  The librtmp library directories.
# - `LIBRTMP_PC_REQUIRES`:   The librtmp pkg-config packages.
# - `LIBRTMP_CFLAGS`:        Required compiler flags.
# - `LIBRTMP_VERSION`:       Version of librtmp.

set(LIBRTMP_PC_REQUIRES "librtmp")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBRTMP_INCLUDE_DIR AND
   NOT DEFINED LIBRTMP_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBRTMP ${LIBRTMP_PC_REQUIRES})
endif()

if(LIBRTMP_FOUND AND LIBRTMP_INCLUDE_DIRS)
  string(REPLACE ";" " " LIBRTMP_CFLAGS "${LIBRTMP_CFLAGS}")
  message(STATUS "Found Librtmp (via pkg-config): ${LIBRTMP_INCLUDE_DIRS} (found version \"${LIBRTMP_VERSION}\")")
else()
  find_path(LIBRTMP_INCLUDE_DIR NAMES "librtmp/rtmp.h")
  find_library(LIBRTMP_LIBRARY NAMES "rtmp")

  unset(LIBRTMP_VERSION CACHE)
  if(LIBRTMP_INCLUDE_DIR AND EXISTS "${LIBRTMP_INCLUDE_DIR}/librtmp/rtmp.h")
    set(_version_regex "#[\t ]*define[\t ]+RTMP_LIB_VERSION[\t ]+0x([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F]).*")
    file(STRINGS "${LIBRTMP_INCLUDE_DIR}/librtmp/rtmp.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str1 "${_version_str}")
    string(REGEX REPLACE "${_version_regex}" "\\2" _version_str2 "${_version_str}")
    if(CMAKE_VERSION VERSION_LESS 3.13)
      # No support for hex version numbers, just strip leading zeroes
      string(REGEX REPLACE "^0" "" _version_str1 "${_version_str1}")
      string(REGEX REPLACE "^0" "" _version_str2 "${_version_str2}")
    else()
      math(EXPR _version_str1 "0x${_version_str1}" OUTPUT_FORMAT DECIMAL)
      math(EXPR _version_str2 "0x${_version_str2}" OUTPUT_FORMAT DECIMAL)
    endif()
    set(LIBRTMP_VERSION "${_version_str1}.${_version_str2}")
    unset(_version_regex)
    unset(_version_str1)
    unset(_version_str2)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Librtmp
    REQUIRED_VARS
      LIBRTMP_INCLUDE_DIR
      LIBRTMP_LIBRARY
    VERSION_VAR
      LIBRTMP_VERSION
  )

  if(LIBRTMP_FOUND)
    set(LIBRTMP_INCLUDE_DIRS ${LIBRTMP_INCLUDE_DIR})
    set(LIBRTMP_LIBRARIES    ${LIBRTMP_LIBRARY})
  endif()

  mark_as_advanced(LIBRTMP_INCLUDE_DIR LIBRTMP_LIBRARY)

  # Necessary when linking a static librtmp
  find_package(OpenSSL)
  if(OPENSSL_FOUND)
    list(APPEND LIBRTMP_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

if(LIBRTMP_FOUND AND WIN32)
  list(APPEND LIBRTMP_LIBRARIES "winmm")
endif()
