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
# SPDX-License-Identifier: curl
#
###########################################################################
include(CheckCSourceCompiles)
# The begin of the sources (macros and includes)
set(_source_epilogue "#undef inline")

macro(add_header_include check header)
  if(${check})
    set(_source_epilogue "${_source_epilogue}\n#include <${header}>")
  endif()
endmacro()

set(signature_call_conv)
if(HAVE_WINDOWS_H)
  add_header_include(HAVE_WINSOCK2_H "winsock2.h")
  add_header_include(HAVE_WINDOWS_H "windows.h")
  set(_source_epilogue
      "${_source_epilogue}\n#ifndef WIN32_LEAN_AND_MEAN\n#define WIN32_LEAN_AND_MEAN\n#endif")
  set(signature_call_conv "PASCAL")
  if(HAVE_LIBWS2_32)
    set(CMAKE_REQUIRED_LIBRARIES ws2_32)
  endif()
else()
  add_header_include(HAVE_SYS_TYPES_H "sys/types.h")
  add_header_include(HAVE_SYS_SOCKET_H "sys/socket.h")
endif()

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

check_c_source_compiles("${_source_epilogue}
  int main(void) {
    int flag = MSG_NOSIGNAL;
    (void)flag;
    return 0;
  }" HAVE_MSG_NOSIGNAL)

if(NOT HAVE_WINDOWS_H)
  add_header_include(HAVE_SYS_TIME_H "sys/time.h")
  add_header_include(TIME_WITH_SYS_TIME "time.h")
  add_header_include(HAVE_TIME_H "time.h")
endif()
check_c_source_compiles("${_source_epilogue}
int main(void) {
  struct timeval ts;
  ts.tv_sec  = 0;
  ts.tv_usec = 0;
  (void)ts;
  return 0;
}" HAVE_STRUCT_TIMEVAL)

if(HAVE_WINDOWS_H)
  set(CMAKE_EXTRA_INCLUDE_FILES winsock2.h)
else()
  set(CMAKE_EXTRA_INCLUDE_FILES)
  if(HAVE_SYS_SOCKET_H)
    set(CMAKE_EXTRA_INCLUDE_FILES sys/socket.h)
  endif()
endif()

check_type_size("struct sockaddr_storage" SIZEOF_STRUCT_SOCKADDR_STORAGE)
if(HAVE_SIZEOF_STRUCT_SOCKADDR_STORAGE)
  set(HAVE_STRUCT_SOCKADDR_STORAGE 1)
endif()

unset(CMAKE_TRY_COMPILE_TARGET_TYPE)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "iOS")
  # only try this on non-apple platforms

  # if not cross-compilation...
  include(CheckCSourceRuns)
  set(CMAKE_REQUIRED_FLAGS "")
  if(HAVE_SYS_POLL_H)
    set(CMAKE_REQUIRED_FLAGS "-DHAVE_SYS_POLL_H")
  elseif(HAVE_POLL_H)
    set(CMAKE_REQUIRED_FLAGS "-DHAVE_POLL_H")
  endif()
  check_c_source_runs("
    #include <stdlib.h>
    #include <sys/time.h>

    #ifdef HAVE_SYS_POLL_H
    #  include <sys/poll.h>
    #elif  HAVE_POLL_H
    #  include <poll.h>
    #endif

    int main(void)
    {
        if(0 != poll(0, 0, 10)) {
          return 1; /* fail */
        }
        else {
          /* detect the 10.12 poll() breakage */
          struct timeval before, after;
          int rc;
          size_t us;

          gettimeofday(&before, NULL);
          rc = poll(NULL, 0, 500);
          gettimeofday(&after, NULL);

          us = (after.tv_sec - before.tv_sec) * 1000000 +
            (after.tv_usec - before.tv_usec);

          if(us < 400000) {
            return 1;
          }
        }
        return 0;
    }" HAVE_POLL_FINE)
  endif()
endif()

