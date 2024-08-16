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
# Find the mbedtls library
#
# Result Variables:
#
# MBEDTLS_FOUND         System has mbedtls
# MBEDTLS_INCLUDE_DIRS  The mbedtls include directories
# MBEDTLS_LIBRARIES     The mbedtls library names
# MBEDTLS_VERSION       Version of mbedtls

# for compatibility. Configuration via MBEDTLS_INCLUDE_DIRS is deprecated, use MBEDTLS_INCLUDE_DIR instead.
if(DEFINED MBEDTLS_INCLUDE_DIRS AND NOT DEFINED MBEDTLS_INCLUDE_DIR)
  set(MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
  unset(MBEDTLS_INCLUDE_DIRS)
endif()

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_MBEDTLS "mbedtls")
endif()

find_path(MBEDTLS_INCLUDE_DIR "mbedtls/ssl.h"
  HINTS
    ${PC_MBEDTLS_INCLUDEDIR}
    ${PC_MBEDTLS_INCLUDE_DIRS}
)

find_library(MBEDTLS_LIBRARY "mbedtls"
  HINTS
    ${PC_MBEDTLS_LIBDIR}
    ${PC_MBEDTLS_LIBRARY_DIRS}
)
find_library(MBEDX509_LIBRARY "mbedx509"
  HINTS
    ${PC_MBEDTLS_LIBDIR}
    ${PC_MBEDTLS_LIBRARY_DIRS}
)
find_library(MBEDCRYPTO_LIBRARY "mbedcrypto"
  HINTS
    ${PC_MBEDTLS_LIBDIR}
    ${PC_MBEDTLS_LIBRARY_DIRS}
)

if(PC_MBEDTLS_VERSION)
  set(MBEDTLS_VERSION ${PC_MBEDTLS_VERSION})
elseif(MBEDTLS_INCLUDE_DIR)
  if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")  # 3.x
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h" _version_header)
  elseif(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")  # 2.x
    file(READ "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h" _version_header)
  else()
    unset(_version_header)
    set(MBEDTLS_VERSION "0.0")
  endif()
  if(_version_header)
    string(REGEX MATCH "#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"([0-9.]+)\"" _version_match "${_version_header}")
    set(MBEDTLS_VERSION "${CMAKE_MATCH_1}")
    unset(_version_header)
    unset(_version_match)
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS
  REQUIRED_VARS
    MBEDTLS_INCLUDE_DIR
    MBEDTLS_LIBRARY
    MBEDX509_LIBRARY
    MBEDCRYPTO_LIBRARY
  VERSION_VAR
    MBEDTLS_VERSION
)

if(MBEDTLS_FOUND)
  set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
  set(MBEDTLS_LIBRARIES    ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
endif()

mark_as_advanced(MBEDTLS_INCLUDE_DIR MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
