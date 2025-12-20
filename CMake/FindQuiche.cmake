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
# Find the quiche library
#
# Input variables:
#
# - `QUICHE_INCLUDE_DIR`:  Absolute path to quiche include directory.
# - `QUICHE_LIBRARY`:      Absolute path to `quiche` library.
#
# Defines:
#
# - `QUICHE_FOUND`:        System has quiche.
# - `QUICHE_VERSION`:      Version of quiche.
# - `CURL::quiche`:        quiche library target.

set(_quiche_pc_requires "quiche")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED QUICHE_INCLUDE_DIR AND
   NOT DEFINED QUICHE_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_quiche ${_quiche_pc_requires})
endif()

if(_quiche_FOUND)
  set(Quiche_FOUND TRUE)
  set(QUICHE_FOUND TRUE)
  set(QUICHE_VERSION ${_quiche_VERSION})
  message(STATUS "Found Quiche (via pkg-config): ${_quiche_INCLUDE_DIRS} (found version \"${QUICHE_VERSION}\")")
else()
  find_path(QUICHE_INCLUDE_DIR NAMES "quiche.h")
  find_library(QUICHE_LIBRARY NAMES "quiche")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Quiche
    REQUIRED_VARS
      QUICHE_INCLUDE_DIR
      QUICHE_LIBRARY
  )

  if(QUICHE_FOUND)
    set(_quiche_INCLUDE_DIRS ${QUICHE_INCLUDE_DIR})
    set(_quiche_LIBRARIES    ${QUICHE_LIBRARY})
  endif()

  mark_as_advanced(QUICHE_INCLUDE_DIR QUICHE_LIBRARY)
endif()

if(QUICHE_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_quiche_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::quiche)
    add_library(CURL::quiche INTERFACE IMPORTED)
    set_target_properties(CURL::quiche PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_quiche_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_quiche_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_quiche_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_quiche_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_quiche_LIBRARIES}")
  endif()
endif()
