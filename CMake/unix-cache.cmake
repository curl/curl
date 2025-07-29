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
# Based on CI runs for Cygwin/MSYS2, Linux, macOS, FreeBSD, NetBSD, OpenBSD
if(NOT UNIX)
  message(FATAL_ERROR "This file should be included on Unix platforms only")
endif()

if(APPLE OR
   CYGWIN)
  set(HAVE_ACCEPT4 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_ACCEPT4 1)
endif()
set(HAVE_ALARM 1)
if(ANDROID)
  set(HAVE_ARC4RANDOM 1)
else()
  set(HAVE_ARC4RANDOM 0)
endif()
set(HAVE_ARPA_INET_H 1)
set(HAVE_ATOMIC 1)
set(HAVE_BASENAME 1)
set(HAVE_BOOL_T 1)
if(NOT APPLE)
  set(HAVE_CLOCK_GETTIME_MONOTONIC 1)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(HAVE_CLOCK_GETTIME_MONOTONIC_RAW 1)
  else()
    set(HAVE_CLOCK_GETTIME_MONOTONIC_RAW 0)
  endif()
endif()
set(HAVE_CLOSESOCKET 0)
set(HAVE_DECL_FSEEKO 1)
set(HAVE_DIRENT_H 1)
if(APPLE OR
   CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_EVENTFD 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(HAVE_EVENTFD 1)
endif()
set(HAVE_FCNTL 1)
set(HAVE_FCNTL_H 1)
set(HAVE_FCNTL_O_NONBLOCK 1)
set(HAVE_FILE_OFFSET_BITS 1)
set(HAVE_FNMATCH 1)
set(HAVE_FREEADDRINFO 1)
set(HAVE_FSEEKO 1)
if(APPLE)
  set(HAVE_FSETXATTR 1)
  set(HAVE_FSETXATTR_5 0)
  set(HAVE_FSETXATTR_6 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_FSETXATTR 0)
  set(HAVE_FSETXATTR_5 0)
  set(HAVE_FSETXATTR_6 0)
elseif(CYGWIN OR
       CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(HAVE_FSETXATTR 1)
  set(HAVE_FSETXATTR_5 1)
  set(HAVE_FSETXATTR_6 0)
endif()
set(HAVE_FTRUNCATE 1)
set(HAVE_GETADDRINFO 1)
if(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_GETADDRINFO_THREADSAFE 0)
elseif(CYGWIN OR
       CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(HAVE_GETADDRINFO_THREADSAFE 1)
endif()
set(HAVE_GETEUID 1)
if(APPLE OR
   CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
   CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_GETHOSTBYNAME_R 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(HAVE_GETHOSTBYNAME_R 1)
endif()
set(HAVE_GETHOSTBYNAME_R_3 0)
set(HAVE_GETHOSTBYNAME_R_3_REENTRANT 0)
set(HAVE_GETHOSTBYNAME_R_5 0)
set(HAVE_GETHOSTBYNAME_R_5_REENTRANT 0)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_GETHOSTBYNAME_R_6 1)
  set(HAVE_GETHOSTBYNAME_R_6_REENTRANT 1)
else()
  set(HAVE_GETHOSTBYNAME_R_6 0)
  set(HAVE_GETHOSTBYNAME_R_6_REENTRANT 0)
endif()
set(HAVE_GETHOSTNAME 1)
if(NOT ANDROID OR ANDROID_PLATFORM_LEVEL GREATER_EQUAL 24)
  set(HAVE_GETIFADDRS 1)
else()
  set(HAVE_GETIFADDRS 0)
endif()
if(APPLE OR
   CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
   CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
   CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_GETPASS_R 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(HAVE_GETPASS_R 1)
endif()
set(HAVE_GETPEERNAME 1)
set(HAVE_GETPPID 1)
set(HAVE_GETPWUID 1)
set(HAVE_GETPWUID_R 1)
set(HAVE_GETRLIMIT 1)
set(HAVE_GETSOCKNAME 1)
set(HAVE_GETTIMEOFDAY 1)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_GLIBC_STRERROR_R 1)
else()
  set(HAVE_GLIBC_STRERROR_R 0)
endif()
set(HAVE_GMTIME_R 1)
set(HAVE_IFADDRS_H 1)
set(HAVE_IF_NAMETOINDEX 1)
set(HAVE_INET_NTOP 1)
set(HAVE_INET_PTON 1)
set(HAVE_IOCTLSOCKET 0)
set(HAVE_IOCTLSOCKET_CAMEL 0)
set(HAVE_IOCTLSOCKET_CAMEL_FIONBIO 0)
set(HAVE_IOCTLSOCKET_FIONBIO 0)
set(HAVE_IOCTL_FIONBIO 1)
set(HAVE_IOCTL_SIOCGIFADDR 1)
if(CYGWIN)
  set(HAVE_IO_H 1)
else()
  set(HAVE_IO_H 0)
endif()
set(HAVE_LIBGEN_H 1)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_LINUX_TCP_H 1)
else()
  set(HAVE_LINUX_TCP_H 0)
endif()
set(HAVE_LOCALE_H 1)
set(HAVE_LONGLONG 1)
if(APPLE)
  set(HAVE_MACH_ABSOLUTE_TIME 1)
endif()
if(APPLE OR
   CYGWIN)
  set(HAVE_MEMRCHR 0)
else()
  set(HAVE_MEMRCHR 1)
endif()
set(HAVE_MSG_NOSIGNAL 1)
set(HAVE_NETDB_H 1)
if(ANDROID)
  set(HAVE_NETINET_IN6_H 1)
else()
  set(HAVE_NETINET_IN6_H 0)
endif()
set(HAVE_NETINET_IN_H 1)
set(HAVE_NETINET_TCP_H 1)
set(HAVE_NETINET_UDP_H 1)
set(HAVE_NET_IF_H 1)
set(HAVE_OPENDIR 1)
set(HAVE_PIPE 1)
if(APPLE OR
   CYGWIN)
  set(HAVE_PIPE2 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_PIPE2 1)
endif()
set(HAVE_POLL 1)
set(HAVE_POLL_H 1)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_POSIX_STRERROR_R 0)
else()
  set(HAVE_POSIX_STRERROR_R 1)
endif()
set(HAVE_PWD_H 1)
set(HAVE_REALPATH 1)
set(HAVE_RECV 1)
set(HAVE_SA_FAMILY_T 1)
set(HAVE_SCHED_YIELD 1)
set(HAVE_SELECT 1)
set(HAVE_SEND 1)
if(APPLE OR
   CYGWIN)
  set(HAVE_SENDMMSG 0)
else()
  set(HAVE_SENDMMSG 1)
endif()
set(HAVE_SENDMSG 1)
set(HAVE_SETLOCALE 1)
if(CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_SETMODE 0)
else()
  set(HAVE_SETMODE 1)
endif()
set(HAVE_SETRLIMIT 1)
set(HAVE_SETSOCKOPT_SO_NONBLOCK 0)
set(HAVE_SIGACTION 1)
set(HAVE_SIGINTERRUPT 1)
set(HAVE_SIGNAL 1)
set(HAVE_SIGSETJMP 1)
set(HAVE_SNPRINTF 1)
set(HAVE_SOCKADDR_IN6_SIN6_ADDR 1)
set(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1)
set(HAVE_SOCKET 1)
set(HAVE_SOCKETPAIR 1)
set(HAVE_STDATOMIC_H 1)
set(HAVE_STDBOOL_H 1)
set(HAVE_STDDEF_H 1)
set(HAVE_STDINT_H 1)
set(HAVE_STRCASECMP 1)
set(HAVE_STRCMPI 0)
set(HAVE_STRDUP 1)
set(HAVE_STRERROR_R 1)
set(HAVE_STRICMP 0)
set(HAVE_STRINGS_H 1)
if(_CURL_OLD_LINUX)
  set(HAVE_STROPTS_H 1)
else()
  set(HAVE_STROPTS_H 0)  # glibc 2.30 or newer. https://sourceware.org/legacy-ml/libc-alpha/2019-08/msg00029.html
endif()
set(HAVE_STRUCT_SOCKADDR_STORAGE 1)
set(HAVE_STRUCT_TIMEVAL 1)
if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(HAVE_SUSECONDS_T 1)
endif()
if(APPLE OR
   CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(HAVE_SYS_EVENTFD_H 0)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
       CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
       CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
  set(HAVE_SYS_EVENTFD_H 1)
endif()
if(CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_SYS_FILIO_H 0)
else()
  set(HAVE_SYS_FILIO_H 1)
endif()
set(HAVE_SYS_IOCTL_H 1)
set(HAVE_SYS_PARAM_H 1)
set(HAVE_SYS_POLL_H 1)
set(HAVE_SYS_RESOURCE_H 1)
set(HAVE_SYS_SELECT_H 1)
if(CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_SYS_SOCKIO_H 0)
else()
  set(HAVE_SYS_SOCKIO_H 1)
endif()
set(HAVE_SYS_TYPES_H 1)
set(HAVE_SYS_UN_H 1)
if(CYGWIN)
  set(HAVE_SYS_UTIME_H 1)
else()
  set(HAVE_SYS_UTIME_H 0)
endif()
set(HAVE_TERMIOS_H 1)
if(CYGWIN OR
   CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HAVE_TERMIO_H 1)
else()
  set(HAVE_TERMIO_H 0)
endif()
set(HAVE_TIME_T_UNSIGNED 0)
set(HAVE_UNISTD_H 1)
set(HAVE_UTIME 1)
set(HAVE_UTIMES 1)
set(HAVE_UTIME_H 1)
set(HAVE_WRITABLE_ARGV 1)
if(CYGWIN)
  set(HAVE__SETMODE 1)
endif()
set(STDC_HEADERS 1)
set(USE_UNIX_SOCKETS 1)
