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
# Find the libbacktrace library
#
# Input variables:
#
# - `LIBBACKTRACE_INCLUDE_DIR`:   Absolute path to libbacktrace include directory.
# - `LIBBACKTRACE_LIBRARY`:       Absolute path to `libbacktrace` library.
#
# Result variables:
#
# - `LIBBACKTRACE_FOUND`:         System has libbacktrace.
# - `LIBBACKTRACE_INCLUDE_DIRS`:  The libbacktrace include directories.
# - `LIBBACKTRACE_LIBRARIES`:     The libbacktrace library names.

find_path(LIBBACKTRACE_INCLUDE_DIR NAMES "backtrace.h")
find_library(LIBBACKTRACE_LIBRARY NAMES "backtrace" "libbacktrace")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libbacktrace
  REQUIRED_VARS
    LIBBACKTRACE_INCLUDE_DIR
    LIBBACKTRACE_LIBRARY
)

if(LIBBACKTRACE_FOUND)
  set(LIBBACKTRACE_INCLUDE_DIRS ${LIBBACKTRACE_INCLUDE_DIR})
  set(LIBBACKTRACE_LIBRARIES    ${LIBBACKTRACE_LIBRARY})
endif()

mark_as_advanced(LIBBACKTRACE_INCLUDE_DIR LIBBACKTRACE_LIBRARY)
