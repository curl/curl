#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://fetch.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: fetch
#
###########################################################################
option(FETCH_HIDDEN_SYMBOLS "Hide libfetch internal symbols (=hide all symbols that are not officially external)" ON)
mark_as_advanced(FETCH_HIDDEN_SYMBOLS)

if(WIN32 AND (ENABLE_DEBUG OR ENABLE_FETCHDEBUG))
  # We need to export internal debug functions,
  # e.g. fetch_easy_perform_ev() or fetch_dbg_*(),
  # so disable symbol hiding for debug builds and for memory tracking.
  set(FETCH_HIDDEN_SYMBOLS OFF)
elseif(DOS OR AMIGA)
  set(FETCH_HIDDEN_SYMBOLS OFF)
endif()

set(FETCH_HIDES_PRIVATE_SYMBOLS FALSE)
set(FETCH_EXTERN_SYMBOL "")
set(FETCH_CFLAG_SYMBOLS_HIDE "")

if(FETCH_HIDDEN_SYMBOLS)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND NOT MSVC)
    set(FETCH_HIDES_PRIVATE_SYMBOLS TRUE)
    set(FETCH_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
    set(FETCH_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
  elseif(CMAKE_COMPILER_IS_GNUCC)
    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 3.4)
      # Note: This is considered buggy prior to 4.0 but the autotools do not care, so let us ignore that fact
      set(FETCH_HIDES_PRIVATE_SYMBOLS TRUE)
      set(FETCH_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
      set(FETCH_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
    endif()
  elseif(CMAKE_C_COMPILER_ID MATCHES "SunPro" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 8.0)
    set(FETCH_HIDES_PRIVATE_SYMBOLS TRUE)
    set(FETCH_EXTERN_SYMBOL "__global")
    set(FETCH_CFLAG_SYMBOLS_HIDE "-xldscope=hidden")
  elseif(CMAKE_C_COMPILER_ID MATCHES "Intel" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.0)  # Requires 9.1.045
    set(FETCH_HIDES_PRIVATE_SYMBOLS TRUE)
    set(FETCH_EXTERN_SYMBOL "__attribute__((__visibility__(\"default\")))")
    set(FETCH_CFLAG_SYMBOLS_HIDE "-fvisibility=hidden")
  elseif(MSVC)
    set(FETCH_HIDES_PRIVATE_SYMBOLS TRUE)
  endif()
else()
  if(MSVC)
    # Note: This option is prone to export non-fetch extra symbols.
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
  endif()
endif()
