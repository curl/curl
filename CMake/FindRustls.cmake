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
# - `RUSTLS_INCLUDE_DIR`:   The Rustls include directory.
# - `RUSTLS_LIBRARY`:       Path to `rustls` library.
#
# Result variables:
#
# - `RUSTLS_FOUND`:         System has Rustls.
# - `RUSTLS_INCLUDE_DIRS`:  The Rustls include directories.
# - `RUSTLS_LIBRARIES`:     The Rustls library names.
# - `RUSTLS_LIBRARY_DIRS`:  The Rustls library directories.
# - `RUSTLS_CFLAGS`:        Required compiler flags.
# - `RUSTLS_VERSION`:       Version of Rustls.

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED RUSTLS_INCLUDE_DIR AND
   NOT DEFINED RUSTLS_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(RUSTLS "rustls")
endif()

if(RUSTLS_FOUND)
  string(REPLACE ";" " " RUSTLS_CFLAGS "${RUSTLS_CFLAGS}")
  message(STATUS "Found Rustls (via pkg-config): ${RUSTLS_INCLUDE_DIRS} (found version \"${RUSTLS_VERSION}\")")
else()
  find_path(RUSTLS_INCLUDE_DIR NAMES "rustls.h")
  find_library(RUSTLS_LIBRARY NAMES "rustls")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Rustls
    REQUIRED_VARS
      RUSTLS_INCLUDE_DIR
      RUSTLS_LIBRARY
  )

  if(RUSTLS_FOUND)
    set(RUSTLS_INCLUDE_DIRS ${RUSTLS_INCLUDE_DIR})
    set(RUSTLS_LIBRARIES    ${RUSTLS_LIBRARY})
  endif()

  mark_as_advanced(RUSTLS_INCLUDE_DIR RUSTLS_LIBRARY)
endif()

if(APPLE)
  find_library(SECURITY_FRAMEWORK "Security")
  mark_as_advanced(SECURITY_FRAMEWORK)
  if(NOT SECURITY_FRAMEWORK)
    message(FATAL_ERROR "Security framework not found")
  endif()
  list(APPEND RUSTLS_LIBRARIES "-framework Security")

  find_library(FOUNDATION_FRAMEWORK "Foundation")
  mark_as_advanced(FOUNDATION_FRAMEWORK)
  if(NOT FOUNDATION_FRAMEWORK)
    message(FATAL_ERROR "Foundation framework not found")
  endif()
  list(APPEND RUSTLS_LIBRARIES "-framework Foundation")
elseif(NOT WIN32)
  find_library(_pthread_library "pthread")
  if(_pthread_library)
    list(APPEND RUSTLS_LIBRARIES "pthread")
  endif()
  mark_as_advanced(_pthread_library)

  find_library(_dl_library "dl")
  if(_dl_library)
    list(APPEND RUSTLS_LIBRARIES "dl")
  endif()
  mark_as_advanced(_dl_library)

  find_library(_math_library "m")
  if(_math_library)
    list(APPEND RUSTLS_LIBRARIES "m")
  endif()
  mark_as_advanced(_math_library)
endif()
