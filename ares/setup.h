#ifndef ARES_SETUP_H
#define ARES_SETUP_H

/* Copyright (C) 2004 - 2005 by Daniel Stenberg et al
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
/* simple work-around for now, for systems without configure support */
#define ssize_t int
#ifndef _MSC_VER
#define socklen_t int
#endif
#endif

/* Recent autoconf versions define these symbols in config.h. We don't want
   them (since they collide with the libcurl ones when we build
   --enable-debug) so we undef them again here. */
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef VERSION
#undef PACKAGE

/* now typedef our socket type */
#if defined(WIN32) && !defined(WATT32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ares_socket_t;
#define ARES_SOCKET_BAD INVALID_SOCKET
#else
typedef int ares_socket_t;
#define ARES_SOCKET_BAD -1
#endif

/* Assume a few thing unless they're set by configure
 */
#if !defined(HAVE_SYS_TIME_H) && !defined(_MSC_VER)
#define HAVE_SYS_TIME_H
#endif

#if !defined(HAVE_UNISTD_H) && !defined(_MSC_VER)
#define HAVE_UNISTD_H 1
#endif

#if !defined(HAVE_SYS_UIO_H) && !defined(WIN32) && !defined(MSDOS)
#define HAVE_SYS_UIO_H
#endif

#if (defined(WIN32) || defined(WATT32)) && \
   !(defined(__MINGW32__) || defined(NETWARE))
/* protos for the functions we provide in windows_port.c */
int ares_strncasecmp(const char *s1, const char *s2, int n);
int ares_strcasecmp(const char *s1, const char *s2);

/* use this define magic to prevent us from adding symbol names to the library
   that is a high-risk to collide with another libraries' attempts to do the
   same */
#define strncasecmp(a,b,c) ares_strncasecmp(a,b,c)
#define strcasecmp(a,b) ares_strcasecmp(a,b)
#endif

/* IPv6 compatibility */
#if !defined(HAVE_AF_INET6)
#if defined(HAVE_PF_INET6)
#define AF_INET6 PF_INET6
#else
#define AF_INET6 AF_MAX+1
#endif
#endif

#endif /* ARES_SETUP_H */
