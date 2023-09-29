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
include(CheckCSourceRuns)

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
  if(WIN32)
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
endif()
check_c_source_compiles("${_source_epilogue}
#include <time.h>
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

if(NOT CMAKE_CROSSCOMPILING)
  if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin" AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "iOS")
    # only try this on non-apple platforms

    # if not cross-compilation...
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

# Detect HAVE_GETADDRINFO_THREADSAFE

if(WIN32)
  set(HAVE_GETADDRINFO_THREADSAFE ${HAVE_GETADDRINFO})
elseif(NOT HAVE_GETADDRINFO)
  set(HAVE_GETADDRINFO_THREADSAFE FALSE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX" OR
       CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "HP-UX" OR
       CMAKE_SYSTEM_NAME STREQUAL "MidnightBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  set(HAVE_GETADDRINFO_THREADSAFE TRUE)
elseif(CMAKE_SYSTEM_NAME MATCHES "BSD")
  set(HAVE_GETADDRINFO_THREADSAFE FALSE)
endif()

if(NOT DEFINED HAVE_GETADDRINFO_THREADSAFE)

  set(_save_epilogue "${_source_epilogue}")
  set(_source_epilogue "#undef inline")

  add_header_include(HAVE_SYS_SOCKET_H "sys/socket.h")
  add_header_include(HAVE_SYS_TIME_H "sys/time.h")
  add_header_include(HAVE_NETDB_H "netdb.h")

  check_c_source_compiles("${_source_epilogue}
    int main(void)
    {
    #ifdef h_errno
      return 0;
    #else
      force compilation error
    #endif
    }" HAVE_H_ERRNO)

  if(NOT HAVE_H_ERRNO)
    check_c_source_runs("${_source_epilogue}
      int main(void)
      {
        h_errno = 2;
        return h_errno != 0 ? 1 : 0;
      }" HAVE_H_ERRNO_ASSIGNABLE)

    if(NOT HAVE_H_ERRNO_ASSIGNABLE)
      check_c_source_compiles("${_source_epilogue}
        int main(void)
        {
        #if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200809L)
          return 0;
        #elif defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 700)
          return 0;
        #else
          force compilation error
        #endif
        }" HAVE_H_ERRNO_SBS_ISSUE_7)
    endif()
  endif()

  if(HAVE_H_ERRNO OR HAVE_H_ERRNO_ASSIGNABLE OR HAVE_H_ERRNO_SBS_ISSUE_7)
    set(HAVE_GETADDRINFO_THREADSAFE TRUE)
  endif()

  set(_source_epilogue "${_save_epilogue}")
endif()

if(NOT DEFINED HAVE_CLOCK_GETTIME_MONOTONIC_RAW)
  set(_save_epilogue "${_source_epilogue}")
  set(_source_epilogue "#undef inline")

  add_header_include(HAVE_SYS_TYPES_H "sys/types.h")
  add_header_include(HAVE_SYS_TIME_H "sys/time.h")

  check_c_source_compiles("${_source_epilogue}
    #include <time.h>
    int main(void)
    {
      struct timespec ts;
      (void)clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
      return 0;
    }" HAVE_CLOCK_GETTIME_MONOTONIC_RAW)

  set(_source_epilogue "${_save_epilogue}")
endif()
