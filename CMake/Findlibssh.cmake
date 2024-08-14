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
# Find the libssh library
#
# Result Variables:
#
# LIBSSH_FOUND         System has libssh
# LIBSSH_INCLUDE_DIRS  The libssh include directories
# LIBSSH_LIBRARIES     The libssh library names
# LIBSSH_VERSION       Version of libssh

if(CURL_USE_PKGCONFIG)
  find_package(PkgConfig QUIET)
  pkg_check_modules(LIBSSH "libssh")
endif()

if(LIBSSH_FOUND)
  if(NOT DEFINED LIBSSH_LINK_LIBRARIES)
    set(LIBSSH_LINK_LIBRARIES "ssh")  # for find_package() with broken pkg-config (e.g. linux-old CI workflow)
  endif()
  set(LIBSSH_LIBRARIES ${LIBSSH_LINK_LIBRARIES})
else()
  find_path(LIBSSH_INCLUDE_DIR "libssh/libssh.h")
  find_library(LIBSSH_LIBRARY NAMES "ssh" "libssh")

  if(LIBSSH_INCLUDE_DIR)
    if(EXISTS "${LIBSSH_INCLUDE_DIR}/libssh/libssh_version.h")
      set(_version_regex_major "^#define[ \t]+LIBSSH_VERSION_MAJOR[ \t]+([0-9]+).*")
      set(_version_regex_minor "^#define[ \t]+LIBSSH_VERSION_MINOR[ \t]+([0-9]+).*")
      set(_version_regex_micro "^#define[ \t]+LIBSSH_VERSION_MICRO[ \t]+([0-9]+).*")
      file(STRINGS "${LIBSSH_INCLUDE_DIR}/libssh/libssh_version.h" _version_major REGEX "${_version_regex_major}")
      file(STRINGS "${LIBSSH_INCLUDE_DIR}/libssh/libssh_version.h" _version_minor REGEX "${_version_regex_minor}")
      file(STRINGS "${LIBSSH_INCLUDE_DIR}/libssh/libssh_version.h" _version_micro REGEX "${_version_regex_micro}")
      string(REGEX REPLACE "${_version_regex_major}" "\\1" _version_major "${_version_major}")
      string(REGEX REPLACE "${_version_regex_minor}" "\\1" _version_minor "${_version_minor}")
      string(REGEX REPLACE "${_version_regex_micro}" "\\1" _version_micro "${_version_micro}")
      unset(_version_regex_major)
      unset(_version_regex_minor)
      unset(_version_regex_micro)
      set(LIBSSH_VERSION "${_version_major}.${_version_minor}.${_version_micro}")
      unset(_version_major)
      unset(_version_minor)
      unset(_version_micro)
    else()
      set(LIBSSH_VERSION "0.0")
    endif()
  endif()

  set(LIBSSH_INCLUDE_DIRS ${LIBSSH_INCLUDE_DIR})
  set(LIBSSH_LIBRARIES    ${LIBSSH_LIBRARY})

  mark_as_advanced(LIBSSH_INCLUDE_DIR LIBSSH_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libssh
  REQUIRED_VARS
    LIBSSH_INCLUDE_DIRS
    LIBSSH_LIBRARIES
  VERSION_VAR
    LIBSSH_VERSION
)
