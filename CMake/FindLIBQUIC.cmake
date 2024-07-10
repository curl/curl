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

#[=======================================================================[.rst:
FindLIBQUIC
----------

Find the libquic library

Result Variables
^^^^^^^^^^^^^^^^

``LIBQUIC_FOUND``
  System has libquic
``LIBQUIC_LIBRARIES``
  The libraries needed to use libquic
``LIBQUIC_VERSION``
  version of libquic.
#]=======================================================================]

if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_LIBQUIC quic)
endif()

find_library(LIBQUIC_LIBRARY NAMES quic
  HINTS
    ${PC_LIBQUIC_LIBDIR}
    ${PC_LIBQUIC_LIBRARY_DIRS}
)

if(PC_LIBQUIC_VERSION)
  set(LIBQUIC_VERSION ${PC_LIBQUIC_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBQUIC
  REQUIRED_VARS
    LIBQUIC_LIBRARY
  VERSION_VAR LIBQUIC_VERSION
)

if(LIBQUIC_FOUND)
  set(LIBQUIC_LIBRARIES    ${LIBQUIC_LIBRARY})
endif()

mark_as_advanced(LIBQUIC_LIBRARIES)
