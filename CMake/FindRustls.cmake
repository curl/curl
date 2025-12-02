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
# Find the Rustls library
#
# Input variables:
#
# - `RUSTLS_INCLUDE_DIR`:  Absolute path to Rustls include directory.
# - `RUSTLS_LIBRARY`:      Absolute path to `rustls` library.
#
# Defines:
#
# - `RUSTLS_FOUND`:        System has Rustls.
# - `RUSTLS_VERSION`:      Version of Rustls.
# - `CURL::rustls`:        Rustls library target.

set(_rustls_pc_requires "rustls")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED RUSTLS_INCLUDE_DIR AND
   NOT DEFINED RUSTLS_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_rustls ${_rustls_pc_requires})
endif()

if(_rustls_FOUND)
  set(Rustls_FOUND TRUE)
  set(RUSTLS_FOUND TRUE)
  set(RUSTLS_VERSION ${_rustls_VERSION})
  message(STATUS "Found Rustls (via pkg-config): ${_rustls_INCLUDE_DIRS} (found version \"${RUSTLS_VERSION}\")")
else()
  set(_rustls_pc_requires "")  # Depend on pkg-config only when found via pkg-config

  find_path(RUSTLS_INCLUDE_DIR NAMES "rustls.h")
  find_library(RUSTLS_LIBRARY NAMES "rustls")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Rustls
    REQUIRED_VARS
      RUSTLS_INCLUDE_DIR
      RUSTLS_LIBRARY
  )

  if(RUSTLS_FOUND)
    set(_rustls_INCLUDE_DIRS ${RUSTLS_INCLUDE_DIR})
    set(_rustls_LIBRARIES    ${RUSTLS_LIBRARY})
  endif()

  mark_as_advanced(RUSTLS_INCLUDE_DIR RUSTLS_LIBRARY)
endif()

if(RUSTLS_FOUND)
  if(APPLE)
    find_library(SECURITY_FRAMEWORK NAMES "Security")
    mark_as_advanced(SECURITY_FRAMEWORK)
    if(NOT SECURITY_FRAMEWORK)
      message(FATAL_ERROR "Security framework not found")
    endif()
    list(APPEND _rustls_LIBRARIES "-framework Security")

    find_library(FOUNDATION_FRAMEWORK NAMES "Foundation")
    mark_as_advanced(FOUNDATION_FRAMEWORK)
    if(NOT FOUNDATION_FRAMEWORK)
      message(FATAL_ERROR "Foundation framework not found")
    endif()
    list(APPEND _rustls_LIBRARIES "-framework Foundation")
  elseif(NOT WIN32)
    find_library(PTHREAD_LIBRARY NAMES "pthread")
    if(PTHREAD_LIBRARY)
      list(APPEND _rustls_LIBRARIES ${PTHREAD_LIBRARY})
    endif()
    mark_as_advanced(PTHREAD_LIBRARY)

    find_library(DL_LIBRARY NAMES "dl")
    if(DL_LIBRARY)
      list(APPEND _rustls_LIBRARIES ${DL_LIBRARY})
    endif()
    mark_as_advanced(DL_LIBRARY)

    find_library(MATH_LIBRARY NAMES "m")
    if(MATH_LIBRARY)
      list(APPEND _rustls_LIBRARIES ${MATH_LIBRARY})
    endif()
    mark_as_advanced(MATH_LIBRARY)
  endif()
endif()

if(RUSTLS_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_rustls_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::rustls)
    add_library(CURL::rustls INTERFACE IMPORTED)
    set_target_properties(CURL::rustls PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_rustls_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_rustls_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_rustls_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_rustls_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_rustls_LIBRARIES}")
  endif()
endif()
