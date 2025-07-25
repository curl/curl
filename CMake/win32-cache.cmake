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
if(NOT WIN32)
  message(FATAL_ERROR "This file should be included on Windows platform only")
endif()

if(MINGW)
  set(HAVE_BASENAME 1)
  set(HAVE_BOOL_T 1)  # = HAVE_STDBOOL_H
  set(HAVE_DIRENT_H 1)
  set(HAVE_FTRUNCATE 1)
  set(HAVE_GETTIMEOFDAY 1)
  set(HAVE_LIBGEN_H 1)
  set(HAVE_OPENDIR 1)
  set(HAVE_SNPRINTF 1)
  set(HAVE_STDBOOL_H 1)
  set(HAVE_STDDEF_H 1)  # detected by CMake internally in check_type_size()
  set(HAVE_STDINT_H 1)  # detected by CMake internally in check_type_size()
  set(HAVE_STRINGS_H 1)  # wrapper to string.h
  set(HAVE_SYS_PARAM_H 1)
  set(HAVE_UNISTD_H 1)
  set(HAVE_UTIME_H 1)  # wrapper to sys/utime.h
else()
  set(HAVE_DIRENT_H 0)
  set(HAVE_FTRUNCATE 0)
  set(HAVE_GETTIMEOFDAY 0)
  set(HAVE_LIBGEN_H 0)
  set(HAVE_OPENDIR 0)
  set(HAVE_STRINGS_H 0)
  set(HAVE_SYS_PARAM_H 0)
  set(HAVE_UTIME_H 0)
  if(MSVC)
    set(HAVE_UNISTD_H 0)
    set(HAVE_STDDEF_H 1)  # detected by CMake internally in check_type_size()
    if(MSVC_VERSION GREATER_EQUAL 1600)
      set(HAVE_STDINT_H 1)  # detected by CMake internally in check_type_size()
    else()
      set(HAVE_STDINT_H 0)  # detected by CMake internally in check_type_size()
    endif()
    if(MSVC_VERSION GREATER_EQUAL 1800)
      set(HAVE_STDBOOL_H 1)
    else()
      set(HAVE_STDBOOL_H 0)
    endif()
    set(HAVE_BOOL_T "${HAVE_STDBOOL_H}")
    if(MSVC_VERSION GREATER_EQUAL 1900)
      set(HAVE_SNPRINTF 1)
    else()
      set(HAVE_SNPRINTF 0)
    endif()
    set(HAVE_BASENAME 0)
  endif()
endif()

if((CMAKE_C_COMPILER_ID STREQUAL "GNU"   AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 4.9) OR
   (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 3.6))
  # MinGW or clang-cl
  set(HAVE_STDATOMIC_H 1)
  set(HAVE_ATOMIC 1)
else()
  set(HAVE_STDATOMIC_H 0)
  set(HAVE_ATOMIC 0)
endif()

set(HAVE_ACCEPT4 0)
set(HAVE_ALARM 0)
set(HAVE_ARC4RANDOM 0)
set(HAVE_ARPA_INET_H 0)
set(HAVE_CLOSESOCKET 1)
set(HAVE_EVENTFD 0)
set(HAVE_FCNTL 0)
set(HAVE_FCNTL_H 1)
set(HAVE_FCNTL_O_NONBLOCK 0)
set(HAVE_FNMATCH 0)
set(HAVE_FREEADDRINFO 1)  # Available in Windows XP and newer
set(HAVE_FSETXATTR 0)
set(HAVE_GETADDRINFO 1)  # Available in Windows XP and newer
set(HAVE_GETEUID 0)
set(HAVE_GETHOSTBYNAME_R 0)
set(HAVE_GETHOSTBYNAME_R_3 0)
set(HAVE_GETHOSTBYNAME_R_3_REENTRANT 0)
set(HAVE_GETHOSTBYNAME_R_5 0)
set(HAVE_GETHOSTBYNAME_R_5_REENTRANT 0)
set(HAVE_GETHOSTBYNAME_R_6 0)
set(HAVE_GETHOSTBYNAME_R_6_REENTRANT 0)
set(HAVE_GETHOSTNAME 1)
set(HAVE_GETIFADDRS 0)
set(HAVE_GETPASS_R 0)
set(HAVE_GETPEERNAME 1)
set(HAVE_GETPPID 0)
set(HAVE_GETPWUID 0)
set(HAVE_GETPWUID_R 0)
set(HAVE_GETRLIMIT 0)
set(HAVE_GETSOCKNAME 1)
set(HAVE_GLIBC_STRERROR_R 0)
set(HAVE_GMTIME_R 0)
set(HAVE_IFADDRS_H 0)
set(HAVE_INET_NTOP 0)
set(HAVE_INET_PTON 0)
set(HAVE_IOCTLSOCKET 1)
set(HAVE_IOCTLSOCKET_CAMEL 0)
set(HAVE_IOCTLSOCKET_CAMEL_FIONBIO 0)
set(HAVE_IOCTLSOCKET_FIONBIO 1)
set(HAVE_IOCTL_FIONBIO 0)
set(HAVE_IOCTL_SIOCGIFADDR 0)
set(HAVE_IO_H 1)
set(HAVE_LINUX_TCP_H 0)
set(HAVE_LOCALE_H 1)
set(HAVE_MEMRCHR 0)
set(HAVE_MSG_NOSIGNAL 0)
set(HAVE_NETDB_H 0)
set(HAVE_NETINET_IN6_H 0)
set(HAVE_NETINET_IN_H 0)
set(HAVE_NETINET_TCP_H 0)
set(HAVE_NETINET_UDP_H 0)
set(HAVE_NET_IF_H 0)
set(HAVE_PIPE 0)
set(HAVE_PIPE2 0)
set(HAVE_POLL 0)
set(HAVE_POLL_H 0)
set(HAVE_POSIX_STRERROR_R 0)
set(HAVE_PWD_H 0)
set(HAVE_RECV 1)
set(HAVE_SELECT 1)
set(HAVE_SEND 1)
set(HAVE_SENDMMSG 0)
set(HAVE_SENDMSG 0)
set(HAVE_SETLOCALE 1)
set(HAVE_SETMODE 1)
set(HAVE_SETRLIMIT 0)
set(HAVE_SETSOCKOPT_SO_NONBLOCK 0)
set(HAVE_SIGACTION 0)
set(HAVE_SIGINTERRUPT 0)
set(HAVE_SIGNAL 1)
set(HAVE_SIGSETJMP 0)
set(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1)
set(HAVE_SOCKET 1)
set(HAVE_SOCKETPAIR 0)
set(HAVE_STRDUP 1)
set(HAVE_STRERROR_R 0)
set(HAVE_STROPTS_H 0)
set(HAVE_STRUCT_SOCKADDR_STORAGE 1)
set(HAVE_STRUCT_TIMEVAL 1)
set(HAVE_SYS_EVENTFD_H 0)
set(HAVE_SYS_FILIO_H 0)
set(HAVE_SYS_IOCTL_H 0)
set(HAVE_SYS_POLL_H 0)
set(HAVE_SYS_RESOURCE_H 0)
set(HAVE_SYS_SELECT_H 0)
set(HAVE_SYS_SOCKIO_H 0)
set(HAVE_SYS_TYPES_H 1)
set(HAVE_SYS_UN_H 0)
set(HAVE_SYS_UTIME_H 1)
set(HAVE_TERMIOS_H 0)
set(HAVE_TERMIO_H 0)
set(HAVE_TIME_T_UNSIGNED 0)
set(HAVE_UTIME 1)
set(HAVE_UTIMES 0)
set(HAVE__SETMODE 1)
set(STDC_HEADERS 1)

# Types and sizes

set(HAVE_SIZEOF_SA_FAMILY_T 0)
set(HAVE_SIZEOF_SUSECONDS_T 0)

if(MINGW OR MSVC)
  curl_prefill_type_size("INT" 4)
  curl_prefill_type_size("LONG" 4)
  curl_prefill_type_size("LONG_LONG" 8)
  curl_prefill_type_size("__INT64" 8)
  curl_prefill_type_size("CURL_OFF_T" 8)
  # CURL_SOCKET_T, SIZE_T: 8 for _WIN64, 4 otherwise
  # TIME_T: 8 for _WIN64 or UCRT or MSVC and not Windows CE, 4 otherwise
  #   Also 4 for non-UCRT 32-bit when _USE_32BIT_TIME_T is set.
  #   mingw-w64 sets _USE_32BIT_TIME_T unless __MINGW_USE_VC2005_COMPAT is explicit defined.
  if(MSVC)
    set(HAVE_SIZEOF_SSIZE_T 0)
    set(HAVE_FILE_OFFSET_BITS 0)
    curl_prefill_type_size("OFF_T" 4)
  else()
    # SSIZE_T: 8 for _WIN64, 4 otherwise
    set(HAVE_FILE_OFFSET_BITS 1)  # mingw-w64 v3+
    curl_prefill_type_size("OFF_T" 8)  # mingw-w64 v3+
  endif()
endif()

# Windows CE exceptions

if(WINCE)
  set(HAVE_FREEADDRINFO 0)
  set(HAVE_GETADDRINFO 0)
  set(HAVE_LOCALE_H 0)
  set(HAVE_SETLOCALE 0)
  set(HAVE_SETMODE 0)
  set(HAVE_SIGNAL 0)
  set(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 0)
  curl_prefill_type_size("CURL_SOCKET_T" 4)
  curl_prefill_type_size("TIME_T" 4)
  curl_prefill_type_size("SIZE_T" 4)
  if(MINGW32CE)
    set(HAVE_STRTOK_R 0)
    set(HAVE__SETMODE 0)
    set(HAVE_FILE_OFFSET_BITS 0)
    curl_prefill_type_size("SSIZE_T" 4)
    curl_prefill_type_size("OFF_T" 4)
  endif()
endif()
