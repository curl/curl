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
# LDAP_INCLUDE_DIR   The ldap include directory
# LDAP_LIBRARY       Path to ldap library
# LDAP_LBER_LIBRARY  Path to mbedx509 library
#
# Result variables:
#
# LDAP_FOUND         System has ldap
# LDAP_INCLUDE_DIRS  The ldap include directories
# LDAP_LIBRARIES     The ldap library names
# LDAP_LIBRARY_DIRS  The ldap library directories
# LDAP_CFLAGS        Required compiler flags

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED LDAP_INCLUDE_DIR AND
   NOT DEFINED LDAP_LIBRARY AND
   NOT DEFINED LDAP_LBER_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LDAP "ldap")
  pkg_check_modules(LDAP_LBER "lber")
endif()

if(LDAP_FOUND AND LDAP_LBER_FOUND)
  list(APPEND LDAP_LIBRARIES ${LDAP_LBER_LIBRARIES})
  list(REMOVE_DUPLICATES LDAP_LIBRARIES)
  string(REPLACE ";" " " LDAP_CFLAGS "${LDAP_CFLAGS}")
  message(STATUS "Found LDAP (via pkg-config): ${LDAP_INCLUDE_DIRS} (found version \"${LDAP_VERSION}\")")
else()
  find_path(LDAP_INCLUDE_DIR NAMES "ldap.h")
  find_library(LDAP_LIBRARY NAMES "ldap")
  find_library(LDAP_LBER_LIBRARY NAMES "lber")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(LDAP
    REQUIRED_VARS
      LDAP_INCLUDE_DIR
      LDAP_LIBRARY
      LDAP_LBER_LIBRARY
  )

  if(LDAP_FOUND)
    set(LDAP_INCLUDE_DIRS ${LDAP_INCLUDE_DIR})
    set(LDAP_LIBRARIES    ${LDAP_LIBRARY} ${LDAP_LBER_LIBRARY})
  endif()

  mark_as_advanced(LDAP_INCLUDE_DIR LDAP_LIBRARY LDAP_LBER_LIBRARY)
endif()
