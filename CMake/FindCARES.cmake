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
# Find the c-ares library
#
# Result Variables:
#
# CARES_FOUND        System has c-ares
# CARES_INCLUDE_DIR  The c-ares include directory
# CARES_LIBRARY      The c-ares library name

find_path(CARES_INCLUDE_DIR "ares.h")

find_library(CARES_LIBRARY
  NAMES ${CARES_NAMES} "cares"
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CARES
  REQUIRED_VARS
    CARES_INCLUDE_DIR
    CARES_LIBRARY
)

mark_as_advanced(CARES_INCLUDE_DIR CARES_LIBRARY)
