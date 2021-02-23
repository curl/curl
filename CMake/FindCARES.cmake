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
# - Find c-ares
# Find the c-ares includes and library
# This module defines
#  CARES_INCLUDE_DIR, where to find ares.h, etc.
#  CARES_LIBRARIES, the libraries needed to use c-ares.
#  CARES_FOUND, If false, do not try to use c-ares.
# also defined, but not for general use are
# CARES_LIBRARY, where to find the c-ares library.

find_path(CARES_INCLUDE_DIR ares.h)

set(CARES_NAMES ${CARES_NAMES} cares)
find_library(CARES_LIBRARY
  NAMES ${CARES_NAMES}
  )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CARES
    REQUIRED_VARS CARES_LIBRARY CARES_INCLUDE_DIR)

mark_as_advanced(
  CARES_LIBRARY
  CARES_INCLUDE_DIR
  )
