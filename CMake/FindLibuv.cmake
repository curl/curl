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
# Find the libuv library
#
# Input variables:
#
# - `LIBUV_INCLUDE_DIR`:  Absolute path to libuv include directory.
# - `LIBUV_LIBRARY`:      Absolute path to `libuv` library.
#
# Defines:
#
# - `LIBUV_FOUND`:        System has libuv.
# - `LIBUV_VERSION`:      Version of libuv.
# - `CURL::libuv`:        libuv library target.

set(_libuv_pc_requires "libuv")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBUV_INCLUDE_DIR AND
   NOT DEFINED LIBUV_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_libuv ${_libuv_pc_requires})
endif()

if(_libuv_FOUND)
  set(Libuv_FOUND TRUE)
  set(LIBUV_FOUND TRUE)
  set(LIBUV_VERSION ${_libuv_VERSION})
  message(STATUS "Found Libuv (via pkg-config): ${_libuv_INCLUDE_DIRS} (found version \"${LIBUV_VERSION}\")")
else()
  find_path(LIBUV_INCLUDE_DIR NAMES "uv.h")
  find_library(LIBUV_LIBRARY NAMES "uv" "libuv")

  unset(LIBUV_VERSION CACHE)
  if(LIBUV_INCLUDE_DIR AND EXISTS "${LIBUV_INCLUDE_DIR}/uv/version.h")
    set(_version_regex1 "#[\t ]*define[\t ]+UV_VERSION_MAJOR[\t ]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[\t ]+UV_VERSION_MINOR[\t ]+([0-9]+).*")
    set(_version_regex3 "#[\t ]*define[\t ]+UV_VERSION_PATCH[\t ]+([0-9]+).*")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str2 REGEX "${_version_regex2}")
    file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_str3 REGEX "${_version_regex3}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
    set(LIBUV_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
    unset(_version_regex1)
    unset(_version_regex2)
    unset(_version_regex3)
    unset(_version_str1)
    unset(_version_str2)
    unset(_version_str3)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libuv
    REQUIRED_VARS
      LIBUV_INCLUDE_DIR
      LIBUV_LIBRARY
    VERSION_VAR
      LIBUV_VERSION
  )

  if(LIBUV_FOUND)
    set(_libuv_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
    set(_libuv_LIBRARIES    ${LIBUV_LIBRARY})
  endif()

  mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)
endif()

if(LIBUV_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_libuv_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::libuv)
    add_library(CURL::libuv INTERFACE IMPORTED)
    set_target_properties(CURL::libuv PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_libuv_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_libuv_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_libuv_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_libuv_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_libuv_LIBRARIES}")
  endif()
endif()
