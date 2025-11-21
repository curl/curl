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
# Find the wolfSSL library
#
# Input variables:
#
# - `WOLFSSL_INCLUDE_DIR`:  Absolute path to wolfSSL include directory.
# - `WOLFSSL_LIBRARY`:      Absolute path to `wolfssl` library.
#
# Defines:
#
# - `WOLFSSL_FOUND`:        System has wolfSSL.
# - `WOLFSSL_VERSION`:      Version of wolfSSL.
# - `CURL::wolfssl`:        wolfSSL library target.

if(DEFINED WolfSSL_INCLUDE_DIR AND NOT DEFINED WOLFSSL_INCLUDE_DIR)
  message(WARNING "WolfSSL_INCLUDE_DIR is deprecated, use WOLFSSL_INCLUDE_DIR instead.")
  set(WOLFSSL_INCLUDE_DIR "${WolfSSL_INCLUDE_DIR}")
endif()
if(DEFINED WolfSSL_LIBRARY AND NOT DEFINED WOLFSSL_LIBRARY)
  message(WARNING "WolfSSL_LIBRARY is deprecated, use WOLFSSL_LIBRARY instead.")
  set(WOLFSSL_LIBRARY "${WolfSSL_LIBRARY}")
endif()

set(_wolfssl_pc_requires "wolfssl")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED WOLFSSL_INCLUDE_DIR AND
   NOT DEFINED WOLFSSL_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_wolfssl ${_wolfssl_pc_requires})
endif()

if(_wolfssl_FOUND)
  set(WolfSSL_FOUND TRUE)
  set(WOLFSSL_FOUND TRUE)
  set(WOLFSSL_VERSION ${_wolfssl_VERSION})
  message(STATUS "Found WolfSSL (via pkg-config): ${_wolfssl_INCLUDE_DIRS} (found version \"${WOLFSSL_VERSION}\")")
else()
  find_path(WOLFSSL_INCLUDE_DIR NAMES "wolfssl/ssl.h")
  find_library(WOLFSSL_LIBRARY NAMES "wolfssl")

  unset(WOLFSSL_VERSION CACHE)
  if(WOLFSSL_INCLUDE_DIR AND EXISTS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h")
    set(_version_regex "#[\t ]*define[\t ]+LIBWOLFSSL_VERSION_STRING[\t ]+\"([^\"]*)\"")
    file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(WOLFSSL_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(WolfSSL
    REQUIRED_VARS
      WOLFSSL_INCLUDE_DIR
      WOLFSSL_LIBRARY
    VERSION_VAR
      WOLFSSL_VERSION
  )

  if(WOLFSSL_FOUND)
    set(_wolfssl_INCLUDE_DIRS ${WOLFSSL_INCLUDE_DIR})
    set(_wolfssl_LIBRARIES    ${WOLFSSL_LIBRARY})
  endif()

  mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)
endif()

if(WOLFSSL_FOUND)
  if(APPLE)
    find_library(SECURITY_FRAMEWORK NAMES "Security")
    mark_as_advanced(SECURITY_FRAMEWORK)
    if(NOT SECURITY_FRAMEWORK)
      message(FATAL_ERROR "Security framework not found")
    endif()
    list(APPEND _wolfssl_LIBRARIES "-framework Security")

    find_library(COREFOUNDATION_FRAMEWORK NAMES "CoreFoundation")
    mark_as_advanced(COREFOUNDATION_FRAMEWORK)
    if(NOT COREFOUNDATION_FRAMEWORK)
      message(FATAL_ERROR "CoreFoundation framework not found")
    endif()
    list(APPEND _wolfssl_LIBRARIES "-framework CoreFoundation")
  elseif(WIN32)
    list(APPEND _wolfssl_LIBRARIES "crypt32")
  else()
    find_library(MATH_LIBRARY NAMES "m")
    if(MATH_LIBRARY)
      list(APPEND _wolfssl_LIBRARIES ${MATH_LIBRARY})  # for log and pow
    endif()
    mark_as_advanced(MATH_LIBRARY)
  endif()

  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_wolfssl_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::wolfssl)
    add_library(CURL::wolfssl INTERFACE IMPORTED)
    set_target_properties(CURL::wolfssl PROPERTIES
      INTERFACE_LIBCURL_PC_MODULES "${_wolfssl_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_wolfssl_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_wolfssl_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_wolfssl_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_wolfssl_LIBRARIES}")
  endif()
endif()
