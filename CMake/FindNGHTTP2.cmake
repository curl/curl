#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
###########################################################################
include(FindPackageHandleStandardArgs)

find_path(NGHTTP2_INCLUDE_DIR "nghttp2/nghttp2.h")

find_library(NGHTTP2_LIBRARY NAMES nghttp2)

find_package_handle_standard_args(NGHTTP2
    FOUND_VAR
      NGHTTP2_FOUND
    REQUIRED_VARS
      NGHTTP2_LIBRARY
      NGHTTP2_INCLUDE_DIR
)

set(NGHTTP2_INCLUDE_DIRS ${NGHTTP2_INCLUDE_DIR})
set(NGHTTP2_LIBRARIES ${NGHTTP2_LIBRARY})

mark_as_advanced(NGHTTP2_INCLUDE_DIRS NGHTTP2_LIBRARIES)
