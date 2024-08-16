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
# Find the libidn2 library
#
# Result Variables:
#
# LIBIDN2_FOUND         System has libidn2
# LIBIDN2_INCLUDE_DIRS  The libidn2 include directories
# LIBIDN2_LIBRARIES     The libidn2 library names
# LIBIDN2_VERSION       Version of libidn2

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBIDN2 "libidn2")
endif()

if(LIBIDN2_FOUND)
  set(LIBIDN2_LIBRARIES ${LIBIDN2_LINK_LIBRARIES})
else()
  find_path(LIBIDN2_INCLUDE_DIR "idn2.h")
  find_library(LIBIDN2_LIBRARY NAMES "idn2" "libidn2")

  if(LIBIDN2_INCLUDE_DIR)
    if(EXISTS "${LIBIDN2_INCLUDE_DIR}/idn2.h")
      set(_version_regex "#[\t ]*define[\t ]+IDN2_VERSION[\t ]+\"([^\"]*)\"")
      file(STRINGS "${LIBIDN2_INCLUDE_DIR}/idn2.h" _version_str REGEX "${_version_regex}")
      string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
      set(LIBIDN2_VERSION "${_version_str}")
      unset(_version_regex)
      unset(_version_str)
    else()
      set(LIBIDN2_VERSION "0.0")
    endif()
  endif()

  set(LIBIDN2_INCLUDE_DIRS ${LIBIDN2_INCLUDE_DIR})
  set(LIBIDN2_LIBRARIES    ${LIBIDN2_LIBRARY})

  mark_as_advanced(LIBIDN2_INCLUDE_DIR LIBIDN2_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libidn2
  REQUIRED_VARS
    LIBIDN2_INCLUDE_DIRS
    LIBIDN2_LIBRARIES
  VERSION_VAR
    LIBIDN2_VERSION
)
