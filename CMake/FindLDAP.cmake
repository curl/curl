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
# Find the ldap library
#
# Input variables:
#
# - `LDAP_INCLUDE_DIR`:   The ldap include directory.
# - `LDAP_LIBRARY`:       Path to `ldap` library.
# - `LDAP_LBER_LIBRARY`:  Path to `lber` library.
#
# Result variables:
#
# - `LDAP_FOUND`:         System has ldap.
# - `LDAP_INCLUDE_DIRS`:  The ldap include directories.
# - `LDAP_LIBRARIES`:     The ldap library names.
# - `LDAP_LIBRARY_DIRS`:  The ldap library directories.
# - `LDAP_PC_REQUIRES`:   The ldap pkg-config packages.
# - `LDAP_CFLAGS`:        Required compiler flags.
# - `LDAP_VERSION`:       Version of ldap.

set(LDAP_PC_REQUIRES "ldap" "lber")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LDAP_INCLUDE_DIR AND
   NOT DEFINED LDAP_LIBRARY AND
   NOT DEFINED LDAP_LBER_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LDAP ${LDAP_PC_REQUIRES})
endif()

if(LDAP_FOUND)
  set(LDAP_VERSION "${LDAP_ldap_VERSION}")
  string(REPLACE ";" " " LDAP_CFLAGS "${LDAP_CFLAGS}")
  message(STATUS "Found LDAP (via pkg-config): ${LDAP_INCLUDE_DIRS} (found version \"${LDAP_VERSION}\")")
else()
  set(LDAP_PC_REQUIRES "")  # Depend on pkg-config only when found via pkg-config

  # On Apple the SDK LDAP gets picked up from
  # 'MacOSX.sdk/System/Library/Frameworks/LDAP.framework/Headers', which contains
  # ldap.h and lber.h both being stubs to include <ldap.h> and <lber.h>.
  # This causes an infinite inclusion loop in compile. Also do this for libraries
  # to avoid picking up the 'ldap.framework' with a full path.
  set(_save_cmake_system_framework_path ${CMAKE_SYSTEM_FRAMEWORK_PATH})
  set(CMAKE_SYSTEM_FRAMEWORK_PATH "")
  find_path(LDAP_INCLUDE_DIR NAMES "ldap.h")
  find_library(LDAP_LIBRARY NAMES "ldap")
  find_library(LDAP_LBER_LIBRARY NAMES "lber")
  set(CMAKE_SYSTEM_FRAMEWORK_PATH ${_save_cmake_system_framework_path})

  unset(LDAP_VERSION CACHE)
  if(LDAP_INCLUDE_DIR AND EXISTS "${LDAP_INCLUDE_DIR}/ldap_features.h")
    set(_version_regex1 "#[\t ]*define[\t ]+LDAP_VENDOR_VERSION_MAJOR[\t ]+([0-9]+).*")
    set(_version_regex2 "#[\t ]*define[\t ]+LDAP_VENDOR_VERSION_MINOR[\t ]+([0-9]+).*")
    set(_version_regex3 "#[\t ]*define[\t ]+LDAP_VENDOR_VERSION_PATCH[\t ]+([0-9]+).*")
    file(STRINGS "${LDAP_INCLUDE_DIR}/ldap_features.h" _version_str1 REGEX "${_version_regex1}")
    file(STRINGS "${LDAP_INCLUDE_DIR}/ldap_features.h" _version_str2 REGEX "${_version_regex2}")
    file(STRINGS "${LDAP_INCLUDE_DIR}/ldap_features.h" _version_str3 REGEX "${_version_regex3}")
    string(REGEX REPLACE "${_version_regex1}" "\\1" _version_str1 "${_version_str1}")
    string(REGEX REPLACE "${_version_regex2}" "\\1" _version_str2 "${_version_str2}")
    string(REGEX REPLACE "${_version_regex3}" "\\1" _version_str3 "${_version_str3}")
    set(LDAP_VERSION "${_version_str1}.${_version_str2}.${_version_str3}")
    unset(_version_regex1)
    unset(_version_regex2)
    unset(_version_regex3)
    unset(_version_str1)
    unset(_version_str2)
    unset(_version_str3)
  endif()

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LDAP
    REQUIRED_VARS
      LDAP_INCLUDE_DIR
      LDAP_LIBRARY
      LDAP_LBER_LIBRARY
    VERSION_VAR
      LDAP_VERSION
  )

  if(LDAP_FOUND)
    set(LDAP_INCLUDE_DIRS ${LDAP_INCLUDE_DIR})
    set(LDAP_LIBRARIES    ${LDAP_LIBRARY} ${LDAP_LBER_LIBRARY})
  endif()

  mark_as_advanced(LDAP_INCLUDE_DIR LDAP_LIBRARY LDAP_LBER_LIBRARY)
endif()
