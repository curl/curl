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
# Find the gsasl library
#
# Result Variables:
#
# GSASL_FOUND         System has gsasl
# GSASL_INCLUDE_DIRS  The gsasl include directories
# GSASL_LIBRARIES     The gsasl library names
# GSASL_VERSION       Version of gsasl

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(GSASL "libgsasl")
endif()

if(GSASL_FOUND)
  set(GSASL_LIBRARIES ${GSASL_LINK_LIBRARIES})
else()
  find_path(GSASL_INCLUDE_DIR "gsasl.h")
  find_library(GSASL_LIBRARY NAMES "gsasl" "libgsasl")

  if(GSASL_INCLUDE_DIR)
    if(EXISTS "${GSASL_INCLUDE_DIR}/gsasl-version.h")
      file(STRINGS "${GSASL_INCLUDE_DIR}/gsasl-version.h" _gsasl_version_str REGEX "^#[\t ]+define[\t ]+GSASL_VERSION[\t ]+\"(.*)\"")
      string(REGEX REPLACE "^.*\"([^\"]+)\"" "\\1" GSASL_VERSION "${_gsasl_version_str}")
      unset(_gsasl_version_str)
    else()
      set(GSASL_VERSION "0.0")
    endif()
  endif()

  set(GSASL_INCLUDE_DIRS ${GSASL_INCLUDE_DIR})
  set(GSASL_LIBRARIES    ${GSASL_LIBRARY})

  mark_as_advanced(GSASL_INCLUDE_DIR GSASL_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GSASL
  REQUIRED_VARS
    GSASL_INCLUDE_DIRS
    GSASL_LIBRARIES
  VERSION_VAR
    GSASL_VERSION
)
