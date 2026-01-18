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
# Find the libssh2 library
#
# Input variables:
#
# - `LIBSSH2_INCLUDE_DIR`:      Absolute path to libssh2 include directory.
# - `LIBSSH2_LIBRARY`:          Absolute path to `libssh2` library.
# - `LIBSSH2_USE_STATIC_LIBS`:  Configure for static libssh2 libraries.
#
# Defines:
#
# - `LIBSSH2_FOUND`:            System has libssh2.
# - `LIBSSH2_VERSION`:          Version of libssh2.
# - `CURL::libssh2`:            libssh2 library target.

set(_libssh2_pc_requires "libssh2")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LIBSSH2_INCLUDE_DIR AND
   NOT DEFINED LIBSSH2_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_libssh2 ${_libssh2_pc_requires})
endif()

if(_libssh2_FOUND AND _libssh2_INCLUDE_DIRS)
  set(Libssh2_FOUND TRUE)
  set(LIBSSH2_FOUND TRUE)
  set(LIBSSH2_VERSION ${_libssh2_VERSION})
  if(LIBSSH2_USE_STATIC_LIBS)
    set(_libssh2_CFLAGS       "${_libssh2_STATIC_CFLAGS}")
    set(_libssh2_INCLUDE_DIRS "${_libssh2_STATIC_INCLUDE_DIRS}")
    set(_libssh2_LIBRARY_DIRS "${_libssh2_STATIC_LIBRARY_DIRS}")
    set(_libssh2_LIBRARIES    "${_libssh2_STATIC_LIBRARIES}")
  endif()
  message(STATUS "Found Libssh2 (via pkg-config): ${_libssh2_INCLUDE_DIRS} (found version \"${LIBSSH2_VERSION}\")")
else()
  find_path(LIBSSH2_INCLUDE_DIR NAMES "libssh2.h")
  if(LIBSSH2_USE_STATIC_LIBS)
    find_library(LIBSSH2_LIBRARY NAMES "ssh2_static" "libssh2_static" "ssh2" "libssh2")
  else()
    find_library(LIBSSH2_LIBRARY NAMES "ssh2" "libssh2")
  endif()

  unset(LIBSSH2_VERSION CACHE)
  if(LIBSSH2_INCLUDE_DIR AND EXISTS "${LIBSSH2_INCLUDE_DIR}/libssh2.h")
    set(_version_regex "#[\t ]*define[\t ]+LIBSSH2_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${LIBSSH2_INCLUDE_DIR}/libssh2.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(LIBSSH2_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libssh2
    REQUIRED_VARS
      LIBSSH2_INCLUDE_DIR
      LIBSSH2_LIBRARY
    VERSION_VAR
      LIBSSH2_VERSION
  )

  if(LIBSSH2_FOUND)
    set(_libssh2_INCLUDE_DIRS ${LIBSSH2_INCLUDE_DIR})
    set(_libssh2_LIBRARIES    ${LIBSSH2_LIBRARY})
  endif()

  mark_as_advanced(LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY)
endif()

if(LIBSSH2_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_libssh2_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::libssh2)
    add_library(CURL::libssh2 INTERFACE IMPORTED)
    set_target_properties(CURL::libssh2 PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_libssh2_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_libssh2_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_libssh2_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_libssh2_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_libssh2_LIBRARIES}")
  endif()
endif()
