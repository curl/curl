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
# Find the GnuTLS library
#
# Input variables:
#
# - `GNUTLS_INCLUDE_DIR`:  Absolute path to GnuTLS include directory.
# - `GNUTLS_LIBRARY`:      Absolute path to `gnutls` library.
#
# Defines:
#
# - `GNUTLS_FOUND`:        System has GnuTLS.
# - `GNUTLS_VERSION`:      Version of GnuTLS.
# - `CURL::gnutls`:        GnuTLS library target.

set(_gnutls_pc_requires "gnutls")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED GNUTLS_INCLUDE_DIR AND
   NOT DEFINED GNUTLS_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_gnutls ${_gnutls_pc_requires})
endif()

if(_gnutls_FOUND)
  set(GnuTLS_FOUND TRUE)
  set(GNUTLS_FOUND TRUE)
  set(GNUTLS_VERSION ${_gnutls_VERSION})
  message(STATUS "Found GnuTLS (via pkg-config): ${_gnutls_INCLUDE_DIRS} (found version \"${GNUTLS_VERSION}\")")
else()
  find_path(GNUTLS_INCLUDE_DIR NAMES "gnutls/gnutls.h")
  find_library(GNUTLS_LIBRARY NAMES "gnutls" "libgnutls")

  unset(GNUTLS_VERSION CACHE)
  if(GNUTLS_INCLUDE_DIR AND EXISTS "${GNUTLS_INCLUDE_DIR}/gnutls/gnutls.h")
    set(_version_regex "#[\t ]*define[\t ]+GNUTLS_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${GNUTLS_INCLUDE_DIR}/gnutls/gnutls.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(GNUTLS_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(GnuTLS
    REQUIRED_VARS
      GNUTLS_INCLUDE_DIR
      GNUTLS_LIBRARY
    VERSION_VAR
      GNUTLS_VERSION
  )

  if(GNUTLS_FOUND)
    set(_gnutls_INCLUDE_DIRS ${GNUTLS_INCLUDE_DIR})
    set(_gnutls_LIBRARIES    ${GNUTLS_LIBRARY})
  endif()

  mark_as_advanced(GNUTLS_INCLUDE_DIR GNUTLS_LIBRARY)
endif()

if(GNUTLS_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_gnutls_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::gnutls)
    add_library(CURL::gnutls INTERFACE IMPORTED)
    set_target_properties(CURL::gnutls PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_gnutls_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_gnutls_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_gnutls_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_gnutls_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_gnutls_LIBRARIES}")
  endif()
endif()
