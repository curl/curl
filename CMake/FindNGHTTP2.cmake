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
# Find the nghttp2 library
#
# Input variables:
#
# - `NGHTTP2_INCLUDE_DIR`:   Absolute path to nghttp2 include directory.
# - `NGHTTP2_LIBRARY`:       Absolute path to `nghttp2` library.
#
# Defines:
#
# - `NGHTTP2_FOUND`:         System has nghttp2.
# - `NGHTTP2_VERSION`:       Version of nghttp2.
# - `CURL::nghttp2`:         nghttp2 library target.

set(_nghttp2_pc_requires "libnghttp2")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED NGHTTP2_INCLUDE_DIR AND
   NOT DEFINED NGHTTP2_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_nghttp2 ${_nghttp2_pc_requires})
endif()

if(_nghttp2_FOUND)
  set(NGHTTP2_FOUND TRUE)
  string(REPLACE ";" " " _nghttp2_CFLAGS "${_nghttp2_CFLAGS}")
  message(STATUS "Found NGHTTP2 (via pkg-config): ${_nghttp2_INCLUDE_DIRS} (found version \"${NGHTTP2_VERSION}\")")
else()
  find_path(NGHTTP2_INCLUDE_DIR NAMES "nghttp2/nghttp2.h")
  find_library(NGHTTP2_LIBRARY NAMES "nghttp2" "nghttp2_static")

  unset(NGHTTP2_VERSION CACHE)
  if(NGHTTP2_INCLUDE_DIR AND EXISTS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h")
    set(_version_regex "#[\t ]*define[\t ]+NGHTTP2_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(NGHTTP2_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(NGHTTP2
    REQUIRED_VARS
      NGHTTP2_INCLUDE_DIR
      NGHTTP2_LIBRARY
    VERSION_VAR
      NGHTTP2_VERSION
  )

  if(NGHTTP2_FOUND)
    set(_nghttp2_INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIR})
    set(_nghttp2_LIBRARIES    ${NGHTTP2_LIBRARY})
  endif()

  mark_as_advanced(NGHTTP2_INCLUDE_DIR NGHTTP2_LIBRARY)
endif()

if(BEARSSL_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_bearssl_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::bearssl)
    add_library(CURL::bearssl INTERFACE IMPORTED)
    set_target_properties(CURL::bearssl PROPERTIES
      VERSION "${BEARSSL_VERSION}"
      CURL_PC_MODULES "${_bearssl_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_bearssl_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_bearssl_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_bearssl_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_bearssl_LIBRARIES}")
  endif()
endif()
