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
option(CURL_HIDDEN_SYMBOLS "Hide libcurl internal symbols (=hide all symbols that are not officially external)" ON)
mark_as_advanced(CURL_HIDDEN_SYMBOLS)

if(WIN32 AND (ENABLE_DEBUG OR ENABLE_CURLDEBUG))
  # We need to export internal debug functions,
  # e.g. curl_easy_perform_ev() or curl_dbg_*(),
  # so disable symbol hiding for debug builds and for memory tracking.
  set(CURL_HIDDEN_SYMBOLS OFF)
elseif(DOS OR AMIGA OR MINGW32CE)
  set(CURL_HIDDEN_SYMBOLS OFF)
endif()

set(CURL_HIDES_PRIVATE_SYMBOLS FALSE)
set(CURL_EXTERN_SYMBOL "")
set(CURL_CFLAG_SYMBOLS_HIDE "")

if(CURL_HIDDEN_SYMBOLS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
    set(CURL_HIDES_PRIVATE_SYMBOLS TRUE)
    set(CURL_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
    set(CURL_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
  elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 3.4)
      # Note: This is considered buggy prior to 4.0 but the autotools do not care, so let us ignore that fact
      set(CURL_HIDES_PRIVATE_SYMBOLS TRUE)
      set(CURL_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
      set(CURL_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
    endif()
  elseif(CMAKE_C_COMPILER_ID MATCHES "SunPro" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0)
    set(CURL_HIDES_PRIVATE_SYMBOLS TRUE)
    set(CURL_EXTERN_SYMBOL "__global")
    set(CURL_CFLAG_SYMBOLS_HIDE "-xldscope=hidden")
  elseif(CMAKE_C_COMPILER_ID MATCHES "Intel" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 9.0)  # Requires 9.1.045
    set(CURL_HIDES_PRIVATE_SYMBOLS TRUE)
    set(CURL_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
    set(CURL_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
  elseif(MSVC)
    set(CURL_HIDES_PRIVATE_SYMBOLS TRUE)
  endif()
else()
  if(MSVC)
    # Note: This option is prone to export non-curl extra symbols.
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
  endif()
endif()
