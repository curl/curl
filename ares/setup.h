#ifndef ARES_SETUP_H
#define ARES_SETUP_H

/* Copyright (C) 2004 by Daniel Stenberg et al
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
#ifdef WIN32
typedef SOCKET ares_socket_t;
#define ARES_SOCKET_BAD INVALID_SOCKET
#else
typedef int ares_socket_t;
#define ARES_SOCKET_BAD -1
#endif

#endif /* ARES_SETUP_H */
