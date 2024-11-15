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
if(NOT DOS)
  message(FATAL_ERROR "This file should be included on MS-DOS platform only")
endif()

# Note: Some of these may be DJGPP-specific.
set(HAVE_ALARM 1)
set(HAVE_ARPA_INET_H 1)
set(HAVE_ATOMIC 1)
set(HAVE_BOOL_T 1)
set(HAVE_CLOSESOCKET 1)
set(HAVE_DECL_FSEEKO 1)
set(HAVE_DIRENT_H 1)
set(HAVE_FCNTL 1)
set(HAVE_FCNTL_H 1)
set(HAVE_FCNTL_O_NONBLOCK 1)
set(HAVE_FNMATCH 1)
set(HAVE_FREEADDRINFO 1)
set(HAVE_FSEEKO 1)
set(HAVE_FTRUNCATE 1)
set(HAVE_GETADDRINFO 1)
set(HAVE_GETADDRINFO_THREADSAFE 1)
set(HAVE_GETEUID 1)
set(HAVE_GETHOSTNAME 1)
set(HAVE_GETPEERNAME 1)
set(HAVE_GETPPID 1)
set(HAVE_GETPWUID 1)
set(HAVE_GETRLIMIT 1)
set(HAVE_GETSOCKNAME 1)
set(HAVE_GETTIMEOFDAY 1)
set(HAVE_GMTIME_R 1)
set(HAVE_IF_NAMETOINDEX 1)
set(HAVE_INET_NTOP 1)
set(HAVE_INET_PTON 1)
set(HAVE_IO_H 1)
set(HAVE_LOCALE_H 1)
set(HAVE_LONGLONG 1)
set(HAVE_MSG_NOSIGNAL 1)
set(HAVE_NETDB_H 1)
set(HAVE_NETINET_IN_H 1)
set(HAVE_NETINET_TCP_H 1)
set(HAVE_NETINET_UDP_H 1)
set(HAVE_OPENDIR 1)
set(HAVE_PIPE 1)
set(HAVE_POLL 1)
set(HAVE_POLL_H 1)
set(HAVE_POSIX_STRERROR_R 1)
set(HAVE_PWD_H 1)
set(HAVE_RECV 1)
set(HAVE_SA_FAMILY_T 1)
set(HAVE_SELECT 1)
set(HAVE_SEND 1)
set(HAVE_SENDMSG 1)
set(HAVE_SETLOCALE 1)
set(HAVE_SETMODE 1)
set(HAVE_SETRLIMIT 1)
set(HAVE_SIGNAL 1)
set(HAVE_SNPRINTF 1)
set(HAVE_SOCKET 1)
set(HAVE_STDATOMIC_H 1)
set(HAVE_STDBOOL_H 1)
set(HAVE_STRDUP 1)
set(HAVE_STRERROR_R 1)
set(HAVE_STRICMP 1)
set(HAVE_STRINGS_H 1)
set(HAVE_STRTOK_R 1)
set(HAVE_STRTOLL 1)
set(HAVE_STRUCT_SOCKADDR_STORAGE 1)
set(HAVE_STRUCT_TIMEVAL 1)
set(HAVE_SYS_IOCTL_H 1)
set(HAVE_SYS_PARAM_H 1)
set(HAVE_SYS_POLL_H 1)
set(HAVE_SYS_RESOURCE_H 1)
set(HAVE_SYS_SELECT_H 1)
set(HAVE_SYS_SOCKET_H 1)
set(HAVE_SYS_STAT_H 1)
set(HAVE_SYS_TYPES_H 1)
set(HAVE_SYS_UN_H 1)
set(HAVE_SYS_WAIT_H 1)
set(HAVE_UNISTD_H 1)
set(HAVE_UTIME 1)
set(HAVE_UTIMES 1)
set(HAVE_UTIME_H 1)
set(STDC_HEADERS 1)

if(CMAKE_COMPILER_IS_GNUCC)
  set(HAVE_BASENAME 1)
  set(HAVE_SIGACTION 1)
  set(HAVE_SIGSETJMP 1)
  set(HAVE_STRCASECMP 1)
  set(HAVE_SYS_TIME_H 1)
  set(HAVE_TERMIOS_H 1)
endif()
