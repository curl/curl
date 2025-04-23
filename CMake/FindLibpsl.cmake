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
# - `LIBPSL_INCLUDE_DIR`:  Absolute path to libpsl include directory.
# - `LIBPSL_LIBRARY`:      Absolute path to `libpsl` library.
#
# Defines:
#
# - `LIBPSL_FOUND`:        System has libpsl.
# - `LIBPSL_VERSION`:      Version of libpsl.
# - `CURL::libpsl`:        libpsl library target.

set(_libpsl_pc_requires "libpsl")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBPSL_INCLUDE_DIR AND
   NOT DEFINED LIBPSL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_libpsl ${_libpsl_pc_requires})
endif()

if(_libpsl_FOUND AND _libpsl_INCLUDE_DIRS)
  set(Libpsl_FOUND TRUE)
  set(LIBPSL_FOUND TRUE)
  set(LIBPSL_VERSION ${_libpsl_VERSION})
  message(STATUS "Found Libpsl (via pkg-config): ${_libpsl_INCLUDE_DIRS} (found version \"${LIBPSL_VERSION}\")")
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
    set(_libpsl_INCLUDE_DIRS ${LIBPSL_INCLUDE_DIR})
    set(_libpsl_LIBRARIES    ${LIBPSL_LIBRARY})
  endif()

  mark_as_advanced(LIBPSL_INCLUDE_DIR LIBPSL_LIBRARY)
endif()

if(LIBPSL_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_libpsl_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::libpsl)
    add_library(CURL::libpsl INTERFACE IMPORTED)
    set_target_properties(CURL::libpsl PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_libpsl_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_libpsl_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_libpsl_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_libpsl_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_libpsl_LIBRARIES}")
  endif()
endif()
