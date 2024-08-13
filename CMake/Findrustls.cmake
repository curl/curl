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
# Find the rustls library
#
# Result Variables:
#
# RUSTLS_FOUND         System has rustls
# RUSTLS_INCLUDE_DIRS  The rustls include directories
# RUSTLS_LIBRARIES     The rustls library names

find_path(RUSTLS_INCLUDE_DIR "rustls.h")

find_library(RUSTLS_LIBRARY "rustls")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(rustls
  REQUIRED_VARS
    RUSTLS_INCLUDE_DIR
    RUSTLS_LIBRARY
)

if(RUSTLS_FOUND)
  set(RUSTLS_INCLUDE_DIRS ${RUSTLS_INCLUDE_DIR})
  set(RUSTLS_LIBRARIES    ${RUSTLS_LIBRARY})
endif()

mark_as_advanced(RUSTLS_INCLUDE_DIR RUSTLS_LIBRARY)
