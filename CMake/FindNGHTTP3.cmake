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
# Find the nghttp3 library
#
# Input variables:
#
# - `NGHTTP3_INCLUDE_DIR`:  Absolute path to nghttp3 include directory.
# - `NGHTTP3_LIBRARY`:      Absolute path to `nghttp3` library.
#
# Defines:
#
# - `NGHTTP3_FOUND`:        System has nghttp3.
# - `NGHTTP3_VERSION`:      Version of nghttp3.
# - `CURL::nghttp3`:        nghttp3 library target.

set(_nghttp3_pc_requires "libnghttp3")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED NGHTTP3_INCLUDE_DIR AND
   NOT DEFINED NGHTTP3_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_nghttp3 ${_nghttp3_pc_requires})
endif()

if(_nghttp3_FOUND)
  set(NGHTTP3_FOUND TRUE)
  set(NGHTTP3_VERSION ${_nghttp3_VERSION})
  message(STATUS "Found NGHTTP3 (via pkg-config): ${_nghttp3_INCLUDE_DIRS} (found version \"${NGHTTP3_VERSION}\")")
else()
  find_path(NGHTTP3_INCLUDE_DIR NAMES "nghttp3/nghttp3.h")
  find_library(NGHTTP3_LIBRARY NAMES "nghttp3")

  unset(NGHTTP3_VERSION CACHE)
  if(NGHTTP3_INCLUDE_DIR AND EXISTS "${NGHTTP3_INCLUDE_DIR}/nghttp3/version.h")
    set(_version_regex "#[\t ]*define[\t ]+NGHTTP3_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${NGHTTP3_INCLUDE_DIR}/nghttp3/version.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(NGHTTP3_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(NGHTTP3
    REQUIRED_VARS
      NGHTTP3_INCLUDE_DIR
      NGHTTP3_LIBRARY
    VERSION_VAR
      NGHTTP3_VERSION
  )

  if(NGHTTP3_FOUND)
    set(_nghttp3_INCLUDE_DIRS ${NGHTTP3_INCLUDE_DIR})
    set(_nghttp3_LIBRARIES    ${NGHTTP3_LIBRARY})
  endif()

  mark_as_advanced(NGHTTP3_INCLUDE_DIR NGHTTP3_LIBRARY)
endif()

if(NGHTTP3_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_nghttp3_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::nghttp3)
    add_library(CURL::nghttp3 INTERFACE IMPORTED)
    set_target_properties(CURL::nghttp3 PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_nghttp3_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_nghttp3_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_nghttp3_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_nghttp3_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_nghttp3_LIBRARIES}")
  endif()
endif()
