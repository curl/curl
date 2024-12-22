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
# Find the mbedTLS library
#
# Input variables:
#
# - `MBEDTLS_INCLUDE_DIR`:   The mbedTLS include directory.
# - `MBEDTLS_LIBRARY`:       Path to `mbedtls` library.
# - `MBEDX509_LIBRARY`:      Path to `mbedx509` library.
# - `MBEDCRYPTO_LIBRARY`:    Path to `mbedcrypto` library.
#
# Result variables:
#
# - `MBEDTLS_FOUND`:         System has mbedTLS.
# - `MBEDTLS_INCLUDE_DIRS`:  The mbedTLS include directories.
# - `MBEDTLS_LIBRARIES`:     The mbedTLS library names.
# - `MBEDTLS_LIBRARY_DIRS`:  The mbedTLS library directories.
# - `MBEDTLS_PC_REQUIRES`:   The mbedTLS pkg-config packages.
# - `MBEDTLS_CFLAGS`:        Required compiler flags.
# - `MBEDTLS_VERSION`:       Version of mbedTLS.

if(DEFINED MBEDTLS_INCLUDE_DIRS AND NOT DEFINED MBEDTLS_INCLUDE_DIR)
  message(WARNING "MBEDTLS_INCLUDE_DIRS is deprecated, use MBEDTLS_INCLUDE_DIR instead.")
  set(MBEDTLS_INCLUDE_DIR "${MBEDTLS_INCLUDE_DIRS}")
  unset(MBEDTLS_INCLUDE_DIRS)
endif()

set(MBEDTLS_PC_REQUIRES "mbedtls")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED MBEDTLS_INCLUDE_DIR AND
   NOT DEFINED MBEDTLS_LIBRARY AND
   NOT DEFINED MBEDX509_LIBRARY AND
   NOT DEFINED MBEDCRYPTO_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(MBEDTLS ${MBEDTLS_PC_REQUIRES})
  pkg_check_modules(MBEDX509 "mbedx509")
  pkg_check_modules(MBEDCRYPTO "mbedcrypto")
endif()

if(MBEDTLS_FOUND AND MBEDX509_FOUND AND MBEDCRYPTO_FOUND)
  list(APPEND MBEDTLS_LIBRARIES ${MBEDX509_LIBRARIES} ${MBEDCRYPTO_LIBRARIES})
  list(REVERSE MBEDTLS_LIBRARIES)
  list(REMOVE_DUPLICATES MBEDTLS_LIBRARIES)
  list(REVERSE MBEDTLS_LIBRARIES)
  string(REPLACE ";" " " MBEDTLS_CFLAGS "${MBEDTLS_CFLAGS}")
  message(STATUS "Found MbedTLS (via pkg-config): ${MBEDTLS_INCLUDE_DIRS} (found version \"${MBEDTLS_VERSION}\")")
else()
  set(MBEDTLS_PC_REQUIRES "")  # Depend on pkg-config only when found via pkg-config

  find_path(MBEDTLS_INCLUDE_DIR NAMES "mbedtls/ssl.h")
  find_library(MBEDTLS_LIBRARY NAMES "mbedtls" "libmbedtls")
  find_library(MBEDX509_LIBRARY NAMES "mbedx509" "libmbedx509")
  find_library(MBEDCRYPTO_LIBRARY NAMES "mbedcrypto" "libmbedcrypto")

  unset(MBEDTLS_VERSION CACHE)
  if(MBEDTLS_INCLUDE_DIR)
    if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")  # 3.x
      set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h")
    elseif(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")  # 2.x
      set(_version_header "${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h")
    else()
      unset(_version_header)
    endif()
    if(_version_header)
      set(_version_regex "#[\t ]*define[\t ]+MBEDTLS_VERSION_STRING[\t ]+\"([0-9.]+)\"")
      file(STRINGS "${_version_header}" _version_str REGEX "${_version_regex}")
      string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
      set(MBEDTLS_VERSION "${_version_str}")
      unset(_version_regex)
      unset(_version_str)
      unset(_version_header)
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
endif()
