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
# Find the msh3 library
#
# Input variables:
#
# - `MSH3_INCLUDE_DIR`:   The msh3 include directory.
# - `MSH3_LIBRARY`:       Path to `msh3` library.
#
# Result variables:
#
# - `MSH3_FOUND`:         System has msh3.
# - `MSH3_INCLUDE_DIRS`:  The msh3 include directories.
# - `MSH3_LIBRARIES`:     The msh3 library names.
# - `MSH3_LIBRARY_DIRS`:  The msh3 library directories.
# - `MSH3_PC_REQUIRES`:   The msh3 pkg-config packages.
# - `MSH3_CFLAGS`:        Required compiler flags.
# - `MSH3_VERSION`:       Version of msh3.

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED MSH3_INCLUDE_DIR AND
   NOT DEFINED MSH3_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(MSH3 "libmsh3")
endif()

if(MSH3_FOUND)
  set(MSH3_PC_REQUIRES "libmsh3")
  string(REPLACE ";" " " MSH3_CFLAGS "${MSH3_CFLAGS}")
  message(STATUS "Found MSH3 (via pkg-config): ${MSH3_INCLUDE_DIRS} (found version \"${MSH3_VERSION}\")")
else()
  find_path(MSH3_INCLUDE_DIR NAMES "msh3.h")
  find_library(MSH3_LIBRARY NAMES "msh3")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(MSH3
    REQUIRED_VARS
      MSH3_INCLUDE_DIR
      MSH3_LIBRARY
  )

  if(MSH3_FOUND)
    set(MSH3_INCLUDE_DIRS ${MSH3_INCLUDE_DIR})
    set(MSH3_LIBRARIES    ${MSH3_LIBRARY})
  endif()

  mark_as_advanced(MSH3_INCLUDE_DIR MSH3_LIBRARY)
endif()
