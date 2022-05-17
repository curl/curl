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
if(NOT UNIX)
  if(WIN32)
    set(HAVE_LIBDL 0)
    set(HAVE_LIBUCB 0)
    set(HAVE_LIBSOCKET 0)
    set(NOT_NEED_LIBNSL 0)
    set(HAVE_LIBNSL 0)
    set(HAVE_GETHOSTNAME 1)
    set(HAVE_LIBZ 0)

    set(HAVE_DLOPEN 0)

    set(HAVE_ALLOCA_H 0)
    set(HAVE_ARPA_INET_H 0)
    set(HAVE_DLFCN_H 0)
    set(HAVE_FCNTL_H 1)
    set(HAVE_INTTYPES_H 0)
    set(HAVE_IO_H 1)
    set(HAVE_MALLOC_H 1)
    set(HAVE_MEMORY_H 1)
    set(HAVE_NETDB_H 0)
    set(HAVE_NETINET_IF_ETHER_H 0)
    set(HAVE_NETINET_IN_H 0)
    set(HAVE_NET_IF_H 0)
    set(HAVE_PROCESS_H 1)
    set(HAVE_PWD_H 0)
    set(HAVE_SETJMP_H 1)
    set(HAVE_SIGNAL_H 1)
    set(HAVE_SOCKIO_H 0)
    set(HAVE_STDINT_H 0)
    set(HAVE_STDLIB_H 1)
    set(HAVE_STRINGS_H 0)
    set(HAVE_STRING_H 1)
    set(HAVE_SYS_PARAM_H 0)
    set(HAVE_SYS_POLL_H 0)
    set(HAVE_SYS_SELECT_H 0)
    set(HAVE_SYS_SOCKET_H 0)
    set(HAVE_SYS_SOCKIO_H 0)
    set(HAVE_SYS_STAT_H 1)
    set(HAVE_SYS_TIME_H 0)
    set(HAVE_SYS_TYPES_H 1)
    set(HAVE_SYS_UTIME_H 1)
    set(HAVE_TERMIOS_H 0)
    set(HAVE_TERMIO_H 0)
    set(HAVE_TIME_H 1)
    set(HAVE_UNISTD_H 0)
    set(HAVE_UTIME_H 0)
    set(HAVE_X509_H 0)
    set(HAVE_ZLIB_H 0)

    set(HAVE_SIZEOF_LONG_DOUBLE 1)
    set(SIZEOF_LONG_DOUBLE 8)

    set(HAVE_SOCKET 1)
    set(HAVE_POLL 0)
    set(HAVE_SELECT 1)
    set(HAVE_STRDUP 1)
    set(HAVE_STRSTR 1)
    set(HAVE_STRTOK_R 0)
    set(HAVE_STRFTIME 1)
    set(HAVE_UNAME 0)
    set(HAVE_STRCASECMP 0)
    set(HAVE_STRICMP 1)
    set(HAVE_STRCMPI 1)
    set(HAVE_GETTIMEOFDAY 0)
    set(HAVE_INET_ADDR 1)
    set(HAVE_CLOSESOCKET 1)
    set(HAVE_SETVBUF 0)
    set(HAVE_SIGSETJMP 0)
    set(HAVE_GETPASS_R 0)
    set(HAVE_STRLCAT 0)
    set(HAVE_GETPWUID 0)
    set(HAVE_GETEUID 0)
    set(HAVE_UTIME 1)
    set(HAVE_RAND_EGD 0)
    set(HAVE_RAND_SCREEN 0)
    set(HAVE_RAND_STATUS 0)
    set(HAVE_GMTIME_R 0)
    set(HAVE_LOCALTIME_R 0)
    set(HAVE_GETHOSTBYNAME_R 0)
    set(HAVE_SIGNAL_FUNC 1)
    set(HAVE_SIGNAL_MACRO 0)

    set(HAVE_GETHOSTBYNAME_R_3 0)
    set(HAVE_GETHOSTBYNAME_R_3_REENTRANT 0)
    set(HAVE_GETHOSTBYNAME_R_5 0)
    set(HAVE_GETHOSTBYNAME_R_5_REENTRANT 0)
    set(HAVE_GETHOSTBYNAME_R_6 0)
    set(HAVE_GETHOSTBYNAME_R_6_REENTRANT 0)

    set(TIME_WITH_SYS_TIME 0)
    set(HAVE_O_NONBLOCK 0)
    set(HAVE_IN_ADDR_T 0)
    if(ENABLE_IPV6)
      set(HAVE_GETADDRINFO 1)
    else()
      set(HAVE_GETADDRINFO 0)
    endif()
    set(STDC_HEADERS 1)

    set(HAVE_SIGACTION 0)
    set(HAVE_MACRO_SIGSETJMP 0)
  else()
    message("This file should be included on Windows platform only")
  endif()
endif()
