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
# Find the ngtcp2 library
#
# This module accepts optional COMPONENTS to control the crypto library (these are
# mutually exclusive):
#
# - quictls:    Use `libngtcp2_crypto_quictls`.   (choose this for LibreSSL)
# - BoringSSL:  Use `libngtcp2_crypto_boringssl`. (choose this for AWS-LC)
# - wolfSSL:    Use `libngtcp2_crypto_wolfssl`.
# - GnuTLS:     Use `libngtcp2_crypto_gnutls`.
#
# Input variables:
#
# - `NGTCP2_INCLUDE_DIR`:   The ngtcp2 include directory.
# - `NGTCP2_LIBRARY`:       Path to `ngtcp2` library.
#
# Result variables:
#
# - `NGTCP2_FOUND`:         System has ngtcp2.
# - `NGTCP2_INCLUDE_DIRS`:  The ngtcp2 include directories.
# - `NGTCP2_LIBRARIES`:     The ngtcp2 library names.
# - `NGTCP2_LIBRARY_DIRS`:  The ngtcp2 library directories.
# - `NGTCP2_PC_REQUIRES`:   The ngtcp2 pkg-config packages.
# - `NGTCP2_CFLAGS`:        Required compiler flags.
# - `NGTCP2_VERSION`:       Version of ngtcp2.

if(NGTCP2_FIND_COMPONENTS)
  set(_ngtcp2_crypto_backend "")
  foreach(_component IN LISTS NGTCP2_FIND_COMPONENTS)
    if(_component MATCHES "^(BoringSSL|quictls|wolfSSL|GnuTLS)")
      if(_ngtcp2_crypto_backend)
        message(FATAL_ERROR "NGTCP2: Only one crypto library can be selected")
      endif()
      set(_ngtcp2_crypto_backend ${_component})
    endif()
  endforeach()

  if(_ngtcp2_crypto_backend)
    string(TOLOWER "ngtcp2_crypto_${_ngtcp2_crypto_backend}" _crypto_library_lower)
    string(TOUPPER "ngtcp2_crypto_${_ngtcp2_crypto_backend}" _crypto_library_upper)
  endif()
endif()

set(NGTCP2_PC_REQUIRES "libngtcp2")
if(_ngtcp2_crypto_backend)
  set(NGTCP2_CRYPTO_PC_REQUIRES "lib${_crypto_library_lower}")
endif()

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED NGTCP2_INCLUDE_DIR AND
   NOT DEFINED NGTCP2_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(NGTCP2 ${NGTCP2_PC_REQUIRES})
  if(_ngtcp2_crypto_backend)
    pkg_check_modules("${_crypto_library_upper}" ${NGTCP2_CRYPTO_PC_REQUIRES})
  else()
    set("${_crypto_library_upper}_FOUND" TRUE)
  endif()
endif()

list(APPEND NGTCP2_PC_REQUIRES ${NGTCP2_CRYPTO_PC_REQUIRES})

if(NGTCP2_FOUND AND "${${_crypto_library_upper}_FOUND}")
  list(APPEND NGTCP2_LIBRARIES "${${_crypto_library_upper}_LIBRARIES}")
  list(REMOVE_DUPLICATES NGTCP2_LIBRARIES)
  string(REPLACE ";" " " NGTCP2_CFLAGS "${NGTCP2_CFLAGS}")
  message(STATUS "Found NGTCP2 (via pkg-config): ${NGTCP2_INCLUDE_DIRS} (found version \"${NGTCP2_VERSION}\")")
else()
  find_path(NGTCP2_INCLUDE_DIR NAMES "ngtcp2/ngtcp2.h")
  find_library(NGTCP2_LIBRARY NAMES "ngtcp2")

  unset(NGTCP2_VERSION CACHE)
  if(NGTCP2_INCLUDE_DIR AND EXISTS "${NGTCP2_INCLUDE_DIR}/ngtcp2/version.h")
    set(_version_regex "#[\t ]*define[\t ]+NGTCP2_VERSION[\t ]+\"([^\"]*)\"")
    file(STRINGS "${NGTCP2_INCLUDE_DIR}/ngtcp2/version.h" _version_str REGEX "${_version_regex}")
    string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
    set(NGTCP2_VERSION "${_version_str}")
    unset(_version_regex)
    unset(_version_str)
  endif()

  if(_ngtcp2_crypto_backend)
    get_filename_component(_ngtcp2_library_dir "${NGTCP2_LIBRARY}" DIRECTORY)
    find_library(${_crypto_library_upper}_LIBRARY NAMES ${_crypto_library_lower} HINTS ${_ngtcp2_library_dir})

    if(${_crypto_library_upper}_LIBRARY)
      set(NGTCP2_${_ngtcp2_crypto_backend}_FOUND TRUE)
      set(NGTCP2_CRYPTO_LIBRARY ${${_crypto_library_upper}_LIBRARY})
    endif()
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(NGTCP2
    REQUIRED_VARS
      NGTCP2_INCLUDE_DIR
      NGTCP2_LIBRARY
    VERSION_VAR
      NGTCP2_VERSION
    HANDLE_COMPONENTS
  )

  if(NGTCP2_FOUND)
    set(NGTCP2_INCLUDE_DIRS ${NGTCP2_INCLUDE_DIR})
    set(NGTCP2_LIBRARIES    ${NGTCP2_LIBRARY} ${NGTCP2_CRYPTO_LIBRARY})
  endif()

  mark_as_advanced(NGTCP2_INCLUDE_DIR NGTCP2_LIBRARY NGTCP2_CRYPTO_LIBRARY)
endif()
