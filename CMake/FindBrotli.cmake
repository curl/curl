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
# Find the brotli library
#
# Result Variables:
#
# BROTLI_FOUND         System has brotli
# BROTLI_INCLUDE_DIRS  The brotli include directories
# BROTLI_LIBRARIES     The brotli library names

include(FindPackageHandleStandardArgs)

find_path(BROTLI_INCLUDE_DIR "brotli/decode.h")

find_library(BROTLICOMMON_LIBRARY NAMES "brotlicommon")
find_library(BROTLIDEC_LIBRARY NAMES "brotlidec")

find_package_handle_standard_args(Brotli
  FOUND_VAR
    BROTLI_FOUND
  REQUIRED_VARS
    BROTLI_INCLUDE_DIR
    BROTLIDEC_LIBRARY
    BROTLICOMMON_LIBRARY
  FAIL_MESSAGE
    "Could NOT find Brotli"
)

set(BROTLI_INCLUDE_DIRS ${BROTLI_INCLUDE_DIR})
set(BROTLI_LIBRARIES ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})
