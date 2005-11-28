#ifndef __INET_PTON_H
#define __INET_PTON_H
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

int Curl_inet_pton(int, const char *, void *);

#ifdef HAVE_INET_PTON

#if defined(HAVE_NO_INET_PTON_PROTO)
int inet_pton(int af, const char *src, void *dst);
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#define Curl_inet_pton(x,y,z) inet_pton(x,y,z)
#endif

#endif /* __INET_PTON_H */
