#ifndef HEADER_FETCH_HTTP_NEGOTIATE_H
#define HEADER_FETCH_HTTP_NEGOTIATE_H
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

#if !defined(FETCH_DISABLE_HTTP) && defined(USE_SPNEGO)

/* this is for Negotiate header input */
FETCHcode Fetch_input_negotiate(struct Fetch_easy *data, struct connectdata *conn,
                               bool proxy, const char *header);

/* this is for creating Negotiate header output */
FETCHcode Fetch_output_negotiate(struct Fetch_easy *data,
                                struct connectdata *conn, bool proxy);

void Fetch_http_auth_cleanup_negotiate(struct connectdata *conn);

#else /* !FETCH_DISABLE_HTTP && USE_SPNEGO */
#define Fetch_http_auth_cleanup_negotiate(x)
#endif

#endif /* HEADER_FETCH_HTTP_NEGOTIATE_H */
