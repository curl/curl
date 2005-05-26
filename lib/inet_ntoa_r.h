#ifndef __INET_NTOA_R_H
#define __INET_NTOA_R_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

#include "setup.h"

#ifdef HAVE_INET_NTOA_R_2_ARGS
/*
 * uClibc 0.9.26 (at least) doesn't define this prototype. The buffer
 * must be at least 16 characters long.
 */
char *inet_ntoa_r(const struct in_addr in, char buffer[]);

#else
/*
 * My solaris 5.6 system running gcc 2.8.1 does *not* have this prototype
 * in any system include file! Isn't that weird?
 */
char *inet_ntoa_r(const struct in_addr in, char *buffer, int buflen);

#endif

#endif
