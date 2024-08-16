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
# Find the libuv library
#
# Result Variables:
#
# LIBUV_FOUND         System has libuv
# LIBUV_INCLUDE_DIRS  The libuv include directories
# LIBUV_LIBRARIES     The libuv library names
# LIBUV_VERSION       Version of libuv

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBUV "libuv")
endif()

if(LIBUV_FOUND)
  set(LIBUV_LIBRARIES ${LIBUV_LINK_LIBRARIES})
else()
  find_path(LIBUV_INCLUDE_DIR "uv.h")
  find_library(LIBUV_LIBRARY NAMES "uv" "libuv")

  if(LIBUV_INCLUDE_DIR)
    if(EXISTS "${LIBUV_INCLUDE_DIR}/uv/version.h")
      file(STRINGS "${LIBUV_INCLUDE_DIR}/uv/version.h" _version_header)
      string(REGEX MATCH ".*define UV_VERSION_MAJOR *([0-9]+).*define UV_VERSION_MINOR *([0-9]+).*define UV_VERSION_PATCH *([0-9]+)" _version_match "${_version_header}")
      set(LIBUV_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
      unset(_version_header)
      unset(_version_match)
    else()
      set(LIBUV_VERSION "0.0")
    endif()
  endif()

  set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
  set(LIBUV_LIBRARIES    ${LIBUV_LIBRARY})

  mark_as_advanced(LIBUV_INCLUDE_DIR LIBUV_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libuv
  REQUIRED_VARS
    LIBUV_INCLUDE_DIRS
    LIBUV_LIBRARIES
  VERSION_VAR
    LIBUV_VERSION
)
