#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
# - Try to find the libssh2 library
# Once done this will define
#
# LIBSSH2_FOUND - system has the libssh2 library
# LIBSSH2_INCLUDE_DIR - the libssh2 include directory
# LIBSSH2_LIBRARY - the libssh2 library name

find_path(LIBSSH2_INCLUDE_DIR libssh2.h)

find_library(LIBSSH2_LIBRARY NAMES ssh2 libssh2)

if(LIBSSH2_INCLUDE_DIR)
  file(STRINGS "${LIBSSH2_INCLUDE_DIR}/libssh2.h" libssh2_version_str REGEX "^#define[\t ]+LIBSSH2_VERSION[\t ]+\"(.*)\"")
  string(REGEX REPLACE "^.*\"([^\"]+)\"" "\\1"  LIBSSH2_VERSION "${libssh2_version_str}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibSSH2
    REQUIRED_VARS LIBSSH2_LIBRARY LIBSSH2_INCLUDE_DIR
    VERSION_VAR LIBSSH2_VERSION)

mark_as_advanced(LIBSSH2_INCLUDE_DIR LIBSSH2_LIBRARY)
