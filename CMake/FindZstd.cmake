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
# Input variables:
#
# - `ZSTD_INCLUDE_DIR`:      Absolute path to zstd include directory.
# - `ZSTD_LIBRARY`:          Absolute path to `zstd` library.
# - `ZSTD_USE_STATIC_LIBS`:  Configure for static zstd libraries.
#
# Defines:
#
# - `ZSTD_FOUND`:            System has zstd.
# - `ZSTD_VERSION`:          Version of zstd.
# - `CURL::zstd`:            zstd library target.

if(DEFINED Zstd_INCLUDE_DIR AND NOT DEFINED ZSTD_INCLUDE_DIR)
  message(WARNING "Zstd_INCLUDE_DIR is deprecated, use ZSTD_INCLUDE_DIR instead.")
  set(ZSTD_INCLUDE_DIR "${Zstd_INCLUDE_DIR}")
endif()
if(DEFINED Zstd_LIBRARY AND NOT DEFINED ZSTD_LIBRARY)
  message(WARNING "Zstd_LIBRARY is deprecated, use ZSTD_LIBRARY instead.")
  set(ZSTD_LIBRARY "${Zstd_LIBRARY}")
endif()

set(_zstd_pc_requires "libzstd")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED ZSTD_INCLUDE_DIR AND
   NOT DEFINED ZSTD_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_zstd ${_zstd_pc_requires})
endif()

if(_zstd_FOUND)
  set(Zstd_FOUND TRUE)
  set(ZSTD_FOUND TRUE)
  set(ZSTD_VERSION ${_zstd_VERSION})
  if(ZSTD_USE_STATIC_LIBS)
    set(_zstd_CFLAGS       "${_zstd_STATIC_CFLAGS}")
    set(_zstd_INCLUDE_DIRS "${_zstd_STATIC_INCLUDE_DIRS}")
    set(_zstd_LIBRARY_DIRS "${_zstd_STATIC_LIBRARY_DIRS}")
    set(_zstd_LIBRARIES    "${_zstd_STATIC_LIBRARIES}")
  endif()
  message(STATUS "Found Zstd (via pkg-config): ${_zstd_INCLUDE_DIRS} (found version \"${ZSTD_VERSION}\")")
else()
  find_path(ZSTD_INCLUDE_DIR NAMES "zstd.h")
  if(ZSTD_USE_STATIC_LIBS)
    find_library(ZSTD_LIBRARY NAMES "zstd_static" "zstd")
  else()
    find_library(ZSTD_LIBRARY NAMES "zstd")
  endif()

  unset(ZSTD_VERSION CACHE)
  if(ZSTD_INCLUDE_DIR AND EXISTS "${ZSTD_INCLUDE_DIR}/zstd.h")
    set(_version_regex1 "#[\t ]*define[ \t]+ZSTD_VERSION_MAJOR[ \t]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[ \t]+ZSTD_VERSION_MINOR[ \t]+([0-9]+).*")
    set(_version_regex3 "#[\t ]*define[ \t]+ZSTD_VERSION_RELEASE[ \t]+([0-9]+).*")
    file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str2 REGEX "${_version_regex2}")
    file(STRINGS "${ZSTD_INCLUDE_DIR}/zstd.h" _version_str3 REGEX "${_version_regex3}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
    set(ZSTD_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
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
      ZSTD_INCLUDE_DIR
      ZSTD_LIBRARY
    VERSION_VAR
      ZSTD_VERSION
  )

  if(ZSTD_FOUND)
    set(_zstd_INCLUDE_DIRS ${ZSTD_INCLUDE_DIR})
    set(_zstd_LIBRARIES    ${ZSTD_LIBRARY})
  endif()

  mark_as_advanced(ZSTD_INCLUDE_DIR ZSTD_LIBRARY)
endif()

if(ZSTD_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_zstd_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::zstd)
    add_library(CURL::zstd INTERFACE IMPORTED)
    set_target_properties(CURL::zstd PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_zstd_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_zstd_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_zstd_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_zstd_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_zstd_LIBRARIES}")
  endif()
endif()
