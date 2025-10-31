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
# Find the brotli library
#
# Input variables:
#
# - `BROTLI_INCLUDE_DIR`:    Absolute path to brotli include directory.
# - `BROTLICOMMON_LIBRARY`:  Absolute path to `brotlicommon` library.
# - `BROTLIDEC_LIBRARY`:     Absolute path to `brotlidec` library.
#
# Defines:
#
# - `BROTLI_FOUND`:          System has brotli.
# - `BROTLI_VERSION`:        Version of brotli.
# - `CURL::brotli`:          brotli library target.

set(_brotli_pc_requires "libbrotlidec" "libbrotlicommon")  # order is significant: brotlidec then brotlicommon

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED BROTLI_INCLUDE_DIR AND
   NOT DEFINED BROTLICOMMON_LIBRARY AND
   NOT DEFINED BROTLIDEC_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_brotli ${_brotli_pc_requires})
endif()

if(_brotli_FOUND)
  set(Brotli_FOUND TRUE)
  set(BROTLI_FOUND TRUE)
  set(BROTLI_VERSION ${_brotli_libbrotlicommon_VERSION})
  message(STATUS "Found Brotli (via pkg-config): ${_brotli_INCLUDE_DIRS} (found version \"${BROTLI_VERSION}\")")
else()
  find_path(BROTLI_INCLUDE_DIR "brotli/decode.h")
  find_library(BROTLICOMMON_LIBRARY NAMES "brotlicommon")
  find_library(BROTLIDEC_LIBRARY NAMES "brotlidec")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Brotli
    REQUIRED_VARS
      BROTLI_INCLUDE_DIR
      BROTLIDEC_LIBRARY
      BROTLICOMMON_LIBRARY
  )

  if(BROTLI_FOUND)
    set(_brotli_INCLUDE_DIRS ${BROTLI_INCLUDE_DIR})
    set(_brotli_LIBRARIES ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})
  endif()

  mark_as_advanced(BROTLI_INCLUDE_DIR BROTLIDEC_LIBRARY BROTLICOMMON_LIBRARY)
endif()

if(BROTLI_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_brotli_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::brotli)
    add_library(CURL::brotli INTERFACE IMPORTED)
    set_target_properties(CURL::brotli PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_brotli_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_brotli_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_brotli_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_brotli_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_brotli_LIBRARIES}")
  endif()
endif()
