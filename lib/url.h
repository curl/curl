#ifndef __URL_H
#define __URL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * Prototypes for library-wide functions provided by url.c
 */

CURLcode Curl_open(struct SessionHandle **curl);
CURLcode Curl_setopt(struct SessionHandle *data, CURLoption option, ...);
CURLcode Curl_close(struct SessionHandle *data); /* opposite of curl_open() */
CURLcode Curl_connect(struct SessionHandle *, struct connectdata **,
                      bool *async);
CURLcode Curl_async_resolved(struct connectdata *conn);
CURLcode Curl_do(struct connectdata **);
CURLcode Curl_do_more(struct connectdata *);
CURLcode Curl_done(struct connectdata **, CURLcode);
CURLcode Curl_disconnect(struct connectdata *);
CURLcode Curl_protocol_connect(struct connectdata *conn);
bool Curl_ssl_config_matches(struct ssl_config_data* data,
                             struct ssl_config_data* needle);
bool Curl_clone_ssl_config(struct ssl_config_data* source,
                           struct ssl_config_data* dest);
void Curl_free_ssl_config(struct ssl_config_data* sslc);
void Curl_safefree(void *ptr);
#endif
