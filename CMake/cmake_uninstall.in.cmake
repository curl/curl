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
if(NOT EXISTS "@PROJECT_BINARY_DIR@/install_manifest.txt")
  message(FATAL_ERROR "Cannot find install manifest: @PROJECT_BINARY_DIR@/install_manifest.txt")
endif()

if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "@CMAKE_INSTALL_PREFIX@")
endif()
message(${CMAKE_INSTALL_PREFIX})

file(READ "@PROJECT_BINARY_DIR@/install_manifest.txt" _files)
string(REGEX REPLACE "\n" ";" _files "${_files}")
foreach(_file ${_files})
  set(_target "$ENV{DESTDIR}${_file}")
  message(STATUS "Uninstalling ${_target}")
  if(IS_SYMLINK "${_target}" OR EXISTS "${_target}")
    execute_process(COMMAND "@CMAKE_COMMAND@" -E rm -f -- "${_target}")
  else()
    message(STATUS "File does not exist: ${_target}")
  endif()
endforeach()
