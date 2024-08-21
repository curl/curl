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
include(CheckCSourceCompiles)

option(CURL_HIDDEN_SYMBOLS "Hide libcurl internal symbols (=hide all symbols that are not officially external)" ON)
mark_as_advanced(CURL_HIDDEN_SYMBOLS)

if(WIN32 AND (ENABLE_DEBUG OR ENABLE_CURLDEBUG))
  # We need to export internal debug functions,
  # e.g. curl_easy_perform_ev() or curl_dbg_*(),
  # so disable symbol hiding for debug builds and for memory tracking.
  set(CURL_HIDDEN_SYMBOLS OFF)
endif()

if(CURL_HIDDEN_SYMBOLS)
  set(_supports_symbol_hiding FALSE)

  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
    set(_supports_symbol_hiding TRUE)
    set(_symbol_extern "__attribute__ ((__visibility__ (\"default\")))")
    set(_cflag_symbols_hide "-fvisibility=hidden")
  elseif(CMAKE_COMPILER_IS_GNUCC)
    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.4)
      # Note: This is considered buggy prior to 4.0 but the autotools do not care, so let us ignore that fact
      set(_supports_symbol_hiding TRUE)
      set(_symbol_extern "__attribute__ ((__visibility__ (\"default\")))")
      set(_cflag_symbols_hide "-fvisibility=hidden")
    endif()
  elseif(CMAKE_C_COMPILER_ID MATCHES "SunPro" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 8.0)
    set(_supports_symbol_hiding TRUE)
    set(_symbol_extern "__global")
    set(_cflag_symbols_hide "-xldscope=hidden")
  elseif(CMAKE_C_COMPILER_ID MATCHES "Intel" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.0)
    # Note: This should probably just check for version 9.1.045 but I am not 100% sure
    #       so let us do it the same way autotools do.
    set(_supports_symbol_hiding TRUE)
    set(_symbol_extern "__attribute__ ((__visibility__ (\"default\")))")
    set(_cflag_symbols_hide "-fvisibility=hidden")
    check_c_source_compiles("#include <stdio.h>
      int main(void) { printf(\"icc fvisibility bug test\"); return 0; }" _no_bug)
    if(NOT _no_bug)
      set(_supports_symbol_hiding FALSE)
      set(_symbol_extern "")
      set(_cflag_symbols_hide "")
    endif()
  elseif(MSVC)
    set(_supports_symbol_hiding TRUE)
  endif()

  set(CURL_HIDES_PRIVATE_SYMBOLS ${_supports_symbol_hiding})
else()
  if(MSVC)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
  endif()
  set(CURL_HIDES_PRIVATE_SYMBOLS FALSE)
endif()

set(CURL_CFLAG_SYMBOLS_HIDE ${_cflag_symbols_hide})
set(CURL_EXTERN_SYMBOL ${_symbol_extern})
