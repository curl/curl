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
if(NOT UNIX)
  if(WIN32)

    set(HAVE_WINDOWS_H 1)
    set(HAVE_WS2TCPIP_H 1)
    set(HAVE_WINSOCK2_H 1)

    if(MINGW)
      set(HAVE_SNPRINTF 1)
      set(HAVE_UNISTD_H 1)
      set(HAVE_INTTYPES_H 1)
      set(HAVE_STRTOLL 1)
      set(HAVE_BASENAME 1)
    elseif(MSVC)
      if(NOT MSVC_VERSION LESS 1800)
        set(HAVE_INTTYPES_H 1)
        set(HAVE_STRTOLL 1)
      else()
        set(HAVE_INTTYPES_H 0)
        set(HAVE_STRTOLL 0)
      endif()
      if(NOT MSVC_VERSION LESS 1900)
        set(HAVE_SNPRINTF 1)
      else()
        set(HAVE_SNPRINTF 0)
      endif()
      set(HAVE_BASENAME 0)
    endif()

    set(HAVE_LIBSOCKET 0)
    set(HAVE_GETHOSTNAME 1)
    set(HAVE_LIBZ 0)

    set(HAVE_ARC4RANDOM 0)
    set(HAVE_FNMATCH 0)
    set(HAVE_SCHED_YIELD 0)
    set(HAVE_ARPA_INET_H 0)
    set(HAVE_FCNTL_H 1)
    set(HAVE_IFADDRS_H 0)
    set(HAVE_IO_H 1)
    set(HAVE_NETDB_H 0)
    set(HAVE_NETINET_IN_H 0)
    set(HAVE_NETINET_TCP_H 0)
    set(HAVE_NETINET_UDP_H 0)
    set(HAVE_NET_IF_H 0)
    set(HAVE_IOCTL_SIOCGIFADDR 0)
    set(HAVE_POLL_H 0)
    set(HAVE_POLL_FINE 0)
    set(HAVE_PWD_H 0)
    set(HAVE_STRINGS_H 0)
    set(HAVE_SYS_FILIO_H 0)
    set(HAVE_SYS_WAIT_H 0)
    set(HAVE_SYS_IOCTL_H 0)
    set(HAVE_SYS_PARAM_H 0)
    set(HAVE_SYS_POLL_H 0)
    set(HAVE_SYS_RESOURCE_H 0)
    set(HAVE_SYS_SELECT_H 0)
    set(HAVE_SYS_SOCKET_H 0)
    set(HAVE_SYS_SOCKIO_H 0)
    set(HAVE_SYS_STAT_H 1)
    set(HAVE_SYS_TIME_H 0)
    set(HAVE_SYS_TYPES_H 1)
    set(HAVE_SYS_UN_H 0)
    set(HAVE_SYS_UTIME_H 1)
    set(HAVE_TERMIOS_H 0)
    set(HAVE_TERMIO_H 0)
    set(HAVE_UTIME_H 0)

    set(HAVE_FSEEKO 0)
    set(HAVE__FSEEKI64 1)
    set(HAVE_SOCKET 1)
    set(HAVE_SELECT 1)
    set(HAVE_STRDUP 1)
    set(HAVE_STRICMP 1)
    set(HAVE_STRCMPI 1)
    set(HAVE_MEMRCHR 0)
    set(HAVE_GETTIMEOFDAY 0)
    set(HAVE_CLOSESOCKET 1)
    set(HAVE_SIGSETJMP 0)
    set(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1)
    set(HAVE_GETPASS_R 0)
    set(HAVE_GETPWUID 0)
    set(HAVE_GETEUID 0)
    set(HAVE_UTIME 1)
    set(HAVE_GMTIME_R 0)
    set(HAVE_CLOCK_GETTIME_MONOTONIC_RAW 0)
    set(HAVE_GETHOSTBYNAME_R 0)
    set(HAVE_SIGNAL 1)
    set(HAVE_LINUX_TCP_H 0)
    set(HAVE_GLIBC_STRERROR_R 0)
    set(HAVE_MACH_ABSOLUTE_TIME 0)
    set(HAVE_GETIFADDRS 0)

    set(HAVE_GETHOSTBYNAME_R_3 0)
    set(HAVE_GETHOSTBYNAME_R_3_REENTRANT 0)
    set(HAVE_GETHOSTBYNAME_R_5 0)
    set(HAVE_GETHOSTBYNAME_R_5_REENTRANT 0)
    set(HAVE_GETHOSTBYNAME_R_6 0)
    set(HAVE_GETHOSTBYNAME_R_6_REENTRANT 0)

    set(HAVE_O_NONBLOCK 0)
    set(HAVE_IN_ADDR_T 0)
    set(STDC_HEADERS 1)

    set(HAVE_SIGACTION 0)
    set(HAVE_MACRO_SIGSETJMP 0)
  else()
    message("This file should be included on Windows platform only")
  endif()
endif()
