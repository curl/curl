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
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################

#[=======================================================================[.rst:
FindNGHTTP3
----------

Find the nghttp3 library

Result Variables
^^^^^^^^^^^^^^^^

``NGHTTP3_FOUND``
  System has nghttp3
``NGHTTP3_INCLUDE_DIRS``
  The nghttp3 include directories.
``NGHTTP3_LIBRARIES``
  The libraries needed to use nghttp3
``NGHTTP3_VERSION``
  version of nghttp3.
#]=======================================================================]

if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_NGHTTP3 libnghttp3)
endif()

find_path(NGHTTP3_INCLUDE_DIR nghttp3/nghttp3.h
  HINTS
    ${PC_NGHTTP3_INCLUDEDIR}
    ${PC_NGHTTP3_INCLUDE_DIRS}
)

find_library(NGHTTP3_LIBRARY NAMES nghttp3
  HINTS
    ${PC_NGHTTP3_LIBDIR}
    ${PC_NGHTTP3_LIBRARY_DIRS}
)

if(PC_NGHTTP3_VERSION)
  set(NGHTTP3_VERSION ${PC_NGHTTP3_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NGHTTP3
  REQUIRED_VARS
    NGHTTP3_LIBRARY
    NGHTTP3_INCLUDE_DIR
  VERSION_VAR NGHTTP3_VERSION
)

if(NGHTTP3_FOUND)
  set(NGHTTP3_LIBRARIES    ${NGHTTP3_LIBRARY})
  set(NGHTTP3_INCLUDE_DIRS ${NGHTTP3_INCLUDE_DIR})
endif()

mark_as_advanced(NGHTTP3_INCLUDE_DIRS NGHTTP3_LIBRARIES)
