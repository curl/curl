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
set(_manifest "@PROJECT_BINARY_DIR@/install_manifest.txt")
if(NOT EXISTS "${_manifest}")
  message(FATAL_ERROR "Cannot find install manifest: ${_manifest}")
endif()

set(_destdir "$ENV{DESTDIR}")
if(NOT _destdir STREQUAL "")
  message(STATUS "DESTDIR environment: ${_destdir}")
endif()

file(READ "${_manifest}" _files)
string(REGEX REPLACE "\n" ";" _files "${_files}")
foreach(_file IN LISTS _files)
  set(_target "${_destdir}${_file}")
  if(IS_SYMLINK "${_target}" OR EXISTS "${_target}")
    file(REMOVE "${_target}")
    if(IS_SYMLINK "${_target}" OR EXISTS "${_target}")
      message(STATUS "Failed to delete: ${_target}")
    else()
      message(STATUS "Uninstalled: ${_target}")
    endif()
  else()
    message(STATUS "File does not exist: ${_target}")
  endif()
endforeach()
