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
# - `CARES_INCLUDE_DIR`:  Absolute path to c-ares include directory.
# - `CARES_LIBRARY`:      Absolute path to `cares` library.
#
# Defines:
#
# - `CARES_FOUND`:        System has c-ares.
# - `CARES_VERSION`:      Version of c-ares.
# - `CURL::cares`:        c-ares library target.

set(_cares_pc_requires "libcares")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED CARES_INCLUDE_DIR AND
   NOT DEFINED CARES_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_cares ${_cares_pc_requires})
endif()

if(_cares_FOUND)
  set(Cares_FOUND TRUE)
  set(CARES_FOUND TRUE)
  set(CARES_VERSION ${_cares_VERSION})
  message(STATUS "Found Cares (via pkg-config): ${_cares_INCLUDE_DIRS} (found version \"${CARES_VERSION}\")")
else()
  find_path(CARES_INCLUDE_DIR NAMES "ares.h")
  find_library(CARES_LIBRARY NAMES ${CARES_NAMES} "cares")

  unset(CARES_VERSION CACHE)
  if(CARES_INCLUDE_DIR AND EXISTS "${CARES_INCLUDE_DIR}/ares_version.h")
    set(_version_regex1 "#[\t ]*define[\t ]+ARES_VERSION_MAJOR[\t ]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[\t ]+ARES_VERSION_MINOR[\t ]+([0-9]+).*")
    set(_version_regex3 "#[\t ]*define[\t ]+ARES_VERSION_PATCH[\t ]+([0-9]+).*")
    file(STRINGS "${CARES_INCLUDE_DIR}/ares_version.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${CARES_INCLUDE_DIR}/ares_version.h" _version_str2 REGEX "${_version_regex2}")
    file(STRINGS "${CARES_INCLUDE_DIR}/ares_version.h" _version_str3 REGEX "${_version_regex3}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
    set(CARES_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
    unset(_version_regex1)
    unset(_version_regex2)
    unset(_version_regex3)
    unset(_version_str1)
    unset(_version_str2)
    unset(_version_str3)
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
    set(_cares_INCLUDE_DIRS ${CARES_INCLUDE_DIR})
    set(_cares_LIBRARIES    ${CARES_LIBRARY})
  endif()

  mark_as_advanced(CARES_INCLUDE_DIR CARES_LIBRARY)
endif()

if(CARES_FOUND)
  if(WIN32)
    list(APPEND _cares_LIBRARIES "iphlpapi")  # for if_indextoname and others
  endif()

  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_cares_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::cares)
    add_library(CURL::cares INTERFACE IMPORTED)
    set_target_properties(CURL::cares PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_cares_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_cares_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_cares_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_cares_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_cares_LIBRARIES}")
  endif()
endif()
