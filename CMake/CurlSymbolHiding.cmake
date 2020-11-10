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
include(CheckCSourceCompiles)

option(CURL_HIDDEN_SYMBOLS "Set to ON to hide libcurl internal symbols (=hide all symbols that aren't officially external)." ON)
mark_as_advanced(CURL_HIDDEN_SYMBOLS)

if(CURL_HIDDEN_SYMBOLS)
  set(SUPPORTS_SYMBOL_HIDING FALSE)

  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
    set(SUPPORTS_SYMBOL_HIDING TRUE)
    set(_SYMBOL_EXTERN "__attribute__ ((__visibility__ (\"default\")))")
    set(_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
  elseif(CMAKE_COMPILER_IS_GNUCC)
    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.4)
      # note: this is considered buggy prior to 4.0 but the autotools don't care, so let's ignore that fact
      set(SUPPORTS_SYMBOL_HIDING TRUE)
      set(_SYMBOL_EXTERN "__attribute__ ((__visibility__ (\"default\")))")
      set(_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
    endif()
  elseif(CMAKE_C_COMPILER_ID MATCHES "SunPro" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 8.0)
    set(SUPPORTS_SYMBOL_HIDING TRUE)
    set(_SYMBOL_EXTERN "__global")
    set(_CFLAG_SYMBOLS_HIDE "-xldscope=hidden")
  elseif(CMAKE_C_COMPILER_ID MATCHES "Intel" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.0)
    # note: this should probably just check for version 9.1.045 but I'm not 100% sure
    #       so let's do it the same way autotools do.
    set(SUPPORTS_SYMBOL_HIDING TRUE)
    set(_SYMBOL_EXTERN "__attribute__ ((__visibility__ (\"default\")))")
    set(_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
    check_c_source_compiles("#include <stdio.h>
        int main (void) { printf(\"icc fvisibility bug test\"); return 0; }" _no_bug)
    if(NOT _no_bug)
      set(SUPPORTS_SYMBOL_HIDING FALSE)
      set(_SYMBOL_EXTERN "")
      set(_CFLAG_SYMBOLS_HIDE "")
    endif()
  elseif(MSVC)
    set(SUPPORTS_SYMBOL_HIDING TRUE)
  endif()

  set(HIDES_CURL_PRIVATE_SYMBOLS ${SUPPORTS_SYMBOL_HIDING})
elseif(MSVC)
  if(NOT CMAKE_VERSION VERSION_LESS 3.7)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE) #present since 3.4.3 but broken
    set(HIDES_CURL_PRIVATE_SYMBOLS FALSE)
  else()
    message(WARNING "Hiding private symbols regardless CURL_HIDDEN_SYMBOLS being disabled.")
    set(HIDES_CURL_PRIVATE_SYMBOLS TRUE)
  endif()
else()
  set(HIDES_CURL_PRIVATE_SYMBOLS FALSE)
endif()

set(CURL_CFLAG_SYMBOLS_HIDE ${_CFLAG_SYMBOLS_HIDE})
set(CURL_EXTERN_SYMBOL ${_SYMBOL_EXTERN})
