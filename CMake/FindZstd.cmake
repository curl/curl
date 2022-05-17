#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#[=======================================================================[.rst:
FindZstd
----------

Find the zstd library

Result Variables
^^^^^^^^^^^^^^^^

``Zstd_FOUND``
  System has zstd
``Zstd_INCLUDE_DIRS``
  The zstd include directories.
``Zstd_LIBRARIES``
  The libraries needed to use zstd
#]=======================================================================]

if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_Zstd libzstd)
endif()

find_path(Zstd_INCLUDE_DIR zstd.h
  HINTS
    ${PC_Zstd_INCLUDEDIR}
    ${PC_Zstd_INCLUDE_DIRS}
)

find_library(Zstd_LIBRARY NAMES zstd
  HINTS
    ${PC_Zstd_LIBDIR}
    ${PC_Zstd_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Zstd
  REQUIRED_VARS
    Zstd_LIBRARY
    Zstd_INCLUDE_DIR
)

if(Zstd_FOUND)
  set(Zstd_LIBRARIES    ${Zstd_LIBRARY})
  set(Zstd_INCLUDE_DIRS ${Zstd_INCLUDE_DIR})
endif()

mark_as_advanced(Zstd_INCLUDE_DIRS Zstd_LIBRARIES)
