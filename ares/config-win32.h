#ifndef __ARES_CONFIG_WIN32_H
#define __ARES_CONFIG_WIN32_H

/* $Id$ */

/* Copyright (C) 2004 - 2006 by Daniel Stenberg et al
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  M.I.T. makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

/* ================================================================ */
/*    ares/config-win32.h - Hand crafted config file for Windows    */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <getopt.h> header file.  */
#if defined(__MINGW32__)
#define HAVE_GETOPT_H 1
#endif

/* Define if you have the <sys/time.h> header file */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <time.h> header file.  */
#define HAVE_TIME_H 1

/* Define if you have the <unistd.h> header file.  */
#if defined(__MINGW32__) || defined(__WATCOMC__) || defined(__LCC__) || \
    defined(__POCC__)
#define HAVE_UNISTD_H 1
#endif

/* Define if you have the <windows.h> header file.  */
#define HAVE_WINDOWS_H 1

/* Define if you have the <winsock.h> header file.  */
#define HAVE_WINSOCK_H 1

/* Define if you have the <winsock2.h> header file.  */
#define HAVE_WINSOCK2_H 1

/* Define if you have the <ws2tcpip.h> header file.  */
#define HAVE_WS2TCPIP_H 1

/* ---------------------------------------------------------------- */
/*                        OTHER HEADER INFO                         */
/* ---------------------------------------------------------------- */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
/* #define TIME_WITH_SYS_TIME 1 */

/* ---------------------------------------------------------------- */
/*                             FUNCTIONS                            */
/* ---------------------------------------------------------------- */

/* Define if you have the ioctlsocket function.  */
#define HAVE_IOCTLSOCKET 1

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 SOCKET

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 char *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 int

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV int

/* Define if you have the send function. */
#define HAVE_SEND 1

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 SOCKET

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 char *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 int

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV int

/* Specifics for the Watt-32 tcp/ip stack */
#ifdef WATT32
  #define SOCKET              int
  #define NS_INADDRSZ         4
  #define HAVE_ARPA_NAMESER_H 1
  #undef HAVE_WINSOCK_H
  #undef HAVE_WINSOCK2_H
  #undef HAVE_WS2TCPIP_H
#endif

/* ---------------------------------------------------------------- */
/*                          STRUCT RELATED                          */
/* ---------------------------------------------------------------- */

/* Define this if you have struct addrinfo */
#define HAVE_STRUCT_ADDRINFO 1

/* Define this if you have struct sockaddr_storage */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define this if you have struct timeval */
#define HAVE_STRUCT_TIMEVAL 1

/* ---------------------------------------------------------------- */
/*                         IPV6 COMPATIBILITY                       */
/* ---------------------------------------------------------------- */

/* Define this if you have address family AF_INET6 */
#define HAVE_AF_INET6 1

/* Define this if you have protocol family PF_INET6 */
#define HAVE_PF_INET6 1

/* Define this if you have struct in6_addr */
#define HAVE_STRUCT_IN6_ADDR 1

/* Define this if you have struct sockaddr_in6 */
#define HAVE_STRUCT_SOCKADDR_IN6 1

/* Define this if you have sockaddr_in6 with scopeid */
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1


#endif  /* __ARES_CONFIG_WIN32_H */
