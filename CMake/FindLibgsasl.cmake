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
# - `LIBGSASL_INCLUDE_DIR`:  Absolute path to libgsasl include directory.
# - `LIBGSASL_LIBRARY`:      Absolute path to `libgsasl` library.
#
# Defines:
#
# - `LIBGSASL_FOUND`:        System has libgsasl.
# - `LIBGSASL_VERSION`:      Version of libgsasl.
# - `CURL::libgsasl`:        libgsasl library target.

set(_libgsasl_pc_requires "libgsasl")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBGSASL_INCLUDE_DIR AND
   NOT DEFINED LIBGSASL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_libgsasl ${_libgsasl_pc_requires})
endif()

if(_libgsasl_FOUND)
  set(Libgsasl_FOUND TRUE)
  set(LIBGSASL_FOUND TRUE)
  message(STATUS "Found Libgsasl (via pkg-config): ${_libgsasl_INCLUDE_DIRS} (found version \"${LIBGSASL_VERSION}\")")
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
    set(_libgsasl_INCLUDE_DIRS ${LIBGSASL_INCLUDE_DIR})
    set(_libgsasl_LIBRARIES    ${LIBGSASL_LIBRARY})
  endif()

  mark_as_advanced(LIBGSASL_INCLUDE_DIR LIBGSASL_LIBRARY)
endif()

if(LIBGSASL_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_libgsasl_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::libgsasl)
    add_library(CURL::libgsasl INTERFACE IMPORTED)
    set_target_properties(CURL::libgsasl PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_libgsasl_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_libgsasl_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_libgsasl_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_libgsasl_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_libgsasl_LIBRARIES}")
  endif()
endif()
