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
# Defines:
#
# - `MSH3_FOUND`:         System has msh3.
# - `MSH3_VERSION`:       Version of msh3.
# - `CURL::msh3`:         msh3 library target.

set(_msh3_pc_requires "libmsh3")

if(CURL_USE_PKGCONFIG AND
   NOT DEFINED MSH3_INCLUDE_DIR AND
   NOT DEFINED MSH3_LIBRARY)
  find_package(PkgConfig QUIET)
  pkg_check_modules(_msh3 ${_msh3_pc_requires})
endif()

if(_msh3_FOUND)
  set(MSH3_FOUND TRUE)
  set(MSH3_VERSION ${_msh3_VERSION})
  message(STATUS "Found MSH3 (via pkg-config): ${_msh3_INCLUDE_DIRS} (found version \"${MSH3_VERSION}\")")
else()
  set(_msh3_pc_requires "")  # Depend on pkg-config only when found via pkg-config

  find_path(MSH3_INCLUDE_DIR NAMES "msh3.h")
  find_library(MSH3_LIBRARY NAMES "msh3")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(MSH3
    REQUIRED_VARS
      MSH3_INCLUDE_DIR
      MSH3_LIBRARY
  )

  if(MSH3_FOUND)
    set(_msh3_INCLUDE_DIRS ${MSH3_INCLUDE_DIR})
    set(_msh3_LIBRARIES    ${MSH3_LIBRARY})
  endif()

  mark_as_advanced(MSH3_INCLUDE_DIR MSH3_LIBRARY)
endif()

if(MSH3_FOUND)
  if(CMAKE_VERSION VERSION_LESS 3.13)
    link_directories(${_msh3_LIBRARY_DIRS})
  endif()

  if(NOT TARGET CURL::msh3)
    add_library(CURL::msh3 INTERFACE IMPORTED)
    set_target_properties(CURL::msh3 PROPERTIES
      INTERFACE_CURL_PC_MODULES "${_msh3_pc_requires}"
      INTERFACE_COMPILE_OPTIONS "${_msh3_CFLAGS}"
      INTERFACE_INCLUDE_DIRECTORIES "${_msh3_INCLUDE_DIRS}"
      INTERFACE_LINK_DIRECTORIES "${_msh3_LIBRARY_DIRS}"
      INTERFACE_LINK_LIBRARIES "${_msh3_LIBRARIES}")
  endif()
endif()
