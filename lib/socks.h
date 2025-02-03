#ifndef HEADER_FETCH_SOCKS_H
#define HEADER_FETCH_SOCKS_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef FETCH_DISABLE_PROXY
#define Fetch_SOCKS4(a, b, c, d, e) FETCHE_NOT_BUILT_IN
#define Fetch_SOCKS5(a, b, c, d, e, f) FETCHE_NOT_BUILT_IN
#define Fetch_SOCKS_getsock(x, y, z) 0
#else
/*
 * Helper read-from-socket functions. Does the same as Fetch_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior
 */
int Fetch_blockread_all(struct Fetch_cfilter *cf,
                       struct Fetch_easy *data,
                       char *buf,
                       ssize_t buffersize,
                       ssize_t *n);

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * This function handles the SOCKS5 GSS-API negotiation and initialization
 */
FETCHcode Fetch_SOCKS5_gssapi_negotiate(struct Fetch_cfilter *cf,
                                       struct Fetch_easy *data);
#endif

FETCHcode Fetch_cf_socks_proxy_insert_after(struct Fetch_cfilter *cf_at,
                                           struct Fetch_easy *data);

extern struct Fetch_cftype Fetch_cft_socks_proxy;

#endif /* FETCH_DISABLE_PROXY */

#endif /* HEADER_FETCH_SOCKS_H */
