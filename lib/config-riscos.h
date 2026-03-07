#ifndef HEADER_CURL_CONFIG_RISCOS_H
#define HEADER_CURL_CONFIG_RISCOS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/* ================================================================ */
/*               Hand crafted config file for RISC OS               */
/* ================================================================ */

/* Define cpu-machine-OS */
#ifndef CURL_OS
#define CURL_OS "ARM-RISC OS"
#endif

/* Define if you want the built-in manual */
#define USE_MANUAL

/* Define if struct sockaddr_in6 has the sin6_scope_id member */
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1

/* Define if you have the alarm function. */
#define HAVE_ALARM

/* Define if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H

/* Define if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H

/* Define if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE

/* Define if getaddrinfo exists and works */
#define HAVE_GETADDRINFO

/* Define if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME

/* Define if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY

/* Define if you have the `timeval' struct. */
#define HAVE_STRUCT_TIMEVAL

/* Define if you have the <netdb.h> header file. */
#define HAVE_NETDB_H

/* Define if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H

/* Define if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H

/* Define if you have the `select' function. */
#define HAVE_SELECT

/* Define if you have the `signal' function. */
#define HAVE_SIGNAL

/* Define if you have the `socket' function. */
#define HAVE_SOCKET

/* Define if you have the `stricmp' function. */
#define HAVE_STRICMP

/* Define if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H

/* Define if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H

/* Define if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 4

/* Define if you have a working ioctl FIONBIO function. */
#define HAVE_IOCTL_FIONBIO

/* to disable LDAP */
#define CURL_DISABLE_LDAP

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 int

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 void *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 size_t

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV ssize_t

/* Define if you have the send function. */
#define HAVE_SEND 1

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 int

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 void *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 size_t

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV ssize_t

#endif /* HEADER_CURL_CONFIG_RISCOS_H */
