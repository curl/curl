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
# Find the libpsl library
#
# Result Variables:
#
# LIBPSL_FOUND        System has libpsl
# LIBPSL_INCLUDE_DIR  The libpsl include directory
# LIBPSL_LIBRARY      The libpsl library name
# LIBPSL_VERSION      Version of libpsl

find_path(LIBPSL_INCLUDE_DIR "libpsl.h")

find_library(LIBPSL_LIBRARY NAMES "psl" "libpsl")

if(LIBPSL_INCLUDE_DIR)
  file(STRINGS "${LIBPSL_INCLUDE_DIR}/libpsl.h" _libpsl_version_str REGEX "^#define[\t ]+PSL_VERSION[\t ]+\"(.*)\"")
  string(REGEX REPLACE "^.*\"([^\"]+)\"" "\\1"  LIBPSL_VERSION "${_libpsl_version_str}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibPSL
  REQUIRED_VARS
    LIBPSL_INCLUDE_DIR
    LIBPSL_LIBRARY
  VERSION_VAR
    LIBPSL_VERSION
)

mark_as_advanced(LIBPSL_INCLUDE_DIR LIBPSL_LIBRARY)
