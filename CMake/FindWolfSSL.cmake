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
# Find the wolfssl library
#
# Input variables:
#
# WOLFSSL_INCLUDE_DIR   The wolfssl include directory
# WolfSSL_INCLUDE_DIR   The wolfssl include directory (deprecated)
# WOLFSSL_LIBRARY       Path to wolfssl library
# WolfSSL_LIBRARY       Path to wolfssl library (deprecated)
#
# Result variables:
#
# WOLFSSL_FOUND         System has wolfssl
# WOLFSSL_INCLUDE_DIRS  The wolfssl include directories
# WOLFSSL_LIBRARIES     The wolfssl library names
# WOLFSSL_VERSION       Version of wolfssl

if(DEFINED WolfSSL_INCLUDE_DIR AND NOT DEFINED WOLFSSL_INCLUDE_DIR)
  message(WARNING "WolfSSL_INCLUDE_DIR is deprecated, use WOLFSSL_INCLUDE_DIR instead.")
  set(WOLFSSL_INCLUDE_DIR "${WolfSSL_INCLUDE_DIR}")
endif()
if(DEFINED WolfSSL_LIBRARY AND NOT DEFINED WOLFSSL_LIBRARY)
  message(WARNING "WolfSSL_LIBRARY is deprecated, use WOLFSSL_LIBRARY instead.")
  set(WOLFSSL_LIBRARY "${WolfSSL_LIBRARY}")
endif()

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(PC_WOLFSSL "wolfssl")
endif()

find_path(WOLFSSL_INCLUDE_DIR NAMES "wolfssl/ssl.h"
  HINTS
    ${PC_WOLFSSL_INCLUDEDIR}
    ${PC_WOLFSSL_INCLUDE_DIRS}
)

find_library(WOLFSSL_LIBRARY NAMES "wolfssl"
  HINTS
    ${PC_WOLFSSL_LIBDIR}
    ${PC_WOLFSSL_LIBRARY_DIRS}
)

if(PC_WOLFSSL_VERSION)
  set(WOLFSSL_VERSION ${PC_WOLFSSL_VERSION})
elseif(WOLFSSL_INCLUDE_DIR AND EXISTS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h")
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
  set(WOLFSSL_INCLUDE_DIRS ${WOLFSSL_INCLUDE_DIR})
  set(WOLFSSL_LIBRARIES    ${WOLFSSL_LIBRARY})

  if(NOT WIN32)
    find_library(_math_library "m")
    if(_math_library)
      list(APPEND WOLFSSL_LIBRARIES "m")  # for log and pow
    endif()
  endif()
endif()

mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)
