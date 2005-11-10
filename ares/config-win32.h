/* $Id$ */

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

#ifndef __CONFIG_WIN32_H
#define __CONFIG_WIN32_H

#if defined(__MINGW32__)
#define HAVE_GETOPT_H
#endif

#if defined(__MINGW32__) || defined(__WATCOMC__)
#define HAVE_UNISTD_H
#endif

#define HAVE_AF_INET6
#define HAVE_PF_INET6
#define HAVE_IOCTLSOCKET
#define HAVE_STRUCT_IN6_ADDR
#define HAVE_STRUCT_SOCKADDR_IN6
#define HAVE_STRUCT_ADDRINFO

#endif  /* __CONFIG_WIN32_H */
