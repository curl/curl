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
# Find the wolfSSH library
#
# Input variables:
#
# - `WOLFSSH_INCLUDE_DIR`:   The wolfSSH include directory.
# - `WOLFSSH_LIBRARY`:       Path to `wolfssh` library.
#
# Result variables:
#
# - `WOLFSSH_FOUND`:         System has wolfSSH.
# - `WOLFSSH_INCLUDE_DIRS`:  The wolfSSH include directories.
# - `WOLFSSH_LIBRARIES`:     The wolfSSH library names.
# - `WOLFSSH_VERSION`:       Version of wolfSSH.

find_path(WOLFSSH_INCLUDE_DIR NAMES "wolfssh/ssh.h")
find_library(WOLFSSH_LIBRARY NAMES "wolfssh" "libwolfssh")

unset(WOLFSSH_VERSION CACHE)
if(WOLFSSH_INCLUDE_DIR AND EXISTS "${WOLFSSH_INCLUDE_DIR}/wolfssh/version.h")
  set(_version_regex "#[\t ]*define[\t ]+LIBWOLFSSH_VERSION_STRING[\t ]+\"([^\"]*)\"")
  file(STRINGS "${WOLFSSH_INCLUDE_DIR}/wolfssh/version.h" _version_str REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" _version_str "${_version_str}")
  set(WOLFSSH_VERSION "${_version_str}")
  unset(_version_regex)
  unset(_version_str)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WolfSSH
  REQUIRED_VARS
    WOLFSSH_INCLUDE_DIR
    WOLFSSH_LIBRARY
  VERSION_VAR
    WOLFSSH_VERSION
)

if(WOLFSSH_FOUND)
  set(WOLFSSH_INCLUDE_DIRS ${WOLFSSH_INCLUDE_DIR})
  set(WOLFSSH_LIBRARIES    ${WOLFSSH_LIBRARY})
endif()

mark_as_advanced(WOLFSSH_INCLUDE_DIR WOLFSSH_LIBRARY)
