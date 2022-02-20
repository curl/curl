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
###########################################################################

#[=======================================================================[.rst:
FindMSH3
----------

Find the msh3 library

Result Variables
^^^^^^^^^^^^^^^^

``MSH3_FOUND``
  System has msh3
``MSH3_INCLUDE_DIRS``
  The msh3 include directories.
``MSH3_LIBRARIES``
  The libraries needed to use msh3
#]=======================================================================]
if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_MSH3 libmsh3)
endif()

find_path(MSH3_INCLUDE_DIR msh3.h
  HINTS
    ${PC_MSH3_INCLUDEDIR}
    ${PC_MSH3_INCLUDE_DIRS}
)

find_library(MSH3_LIBRARY NAMES msh3
  HINTS
    ${PC_MSH3_LIBDIR}
    ${PC_MSH3_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MSH3
  REQUIRED_VARS
    MSH3_LIBRARY
    MSH3_INCLUDE_DIR
)

if(MSH3_FOUND)
  set(MSH3_LIBRARIES    ${MSH3_LIBRARY})
  set(MSH3_INCLUDE_DIRS ${MSH3_INCLUDE_DIR})
endif()

mark_as_advanced(MSH3_INCLUDE_DIRS MSH3_LIBRARIES)
