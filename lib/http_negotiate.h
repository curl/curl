#ifndef HEADER_CURL_HTTP_NEGOTIATE_H
#define HEADER_CURL_HTTP_NEGOTIATE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#ifdef HAVE_GSSAPI

/* this is for Negotiate header input */
int Curl_input_negotiate(struct connectdata *conn, bool proxy,
                         const char *header);

/* this is for creating Negotiate header output */
CURLcode Curl_output_negotiate(struct connectdata *conn, bool proxy);

void Curl_cleanup_negotiate(struct SessionHandle *data);

#endif /* HAVE_GSSAPI */

#endif /* HEADER_CURL_HTTP_NEGOTIATE_H */
