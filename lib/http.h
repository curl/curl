#ifndef __HTTP_H
#define __HTTP_H

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifndef CURL_DISABLE_HTTP
bool Curl_compareheader(char *headerline,     /* line to check */
                        const char *header,   /* header keyword _with_ colon */
                        const char *content); /* content string to find */

/* ftp can use this as well */
CURLcode Curl_proxyCONNECT(struct connectdata *conn,
                           int tunnelsocket,
                           char *hostname, int remote_port);

/* protocol-specific functions set up to be called by the main engine */
CURLcode Curl_http(struct connectdata *conn, bool *done);
CURLcode Curl_http_done(struct connectdata *, CURLcode, bool premature);
CURLcode Curl_http_connect(struct connectdata *conn, bool *done);
CURLcode Curl_https_connecting(struct connectdata *conn, bool *done);
int Curl_https_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks);

/* The following functions are defined in http_chunks.c */
void Curl_httpchunk_init(struct connectdata *conn);
CHUNKcode Curl_httpchunk_read(struct connectdata *conn, char *datap,
                              ssize_t length, ssize_t *wrote);

/* These functions are in http.c */
void Curl_http_auth_stage(struct SessionHandle *data, int stage);
CURLcode Curl_http_input_auth(struct connectdata *conn,
                              int httpcode, char *header);
CURLcode Curl_http_auth_act(struct connectdata *conn);

int Curl_http_should_fail(struct connectdata *conn);

/* If only the PICKNONE bit is set, there has been a round-trip and we
   selected to use no auth at all. Ie, we actively select no auth, as opposed
   to not having one selected. The other CURLAUTH_* defines are present in the
   public curl/curl.h header. */
#define CURLAUTH_PICKNONE (1<<30) /* don't use auth */

/* MAX_INITIAL_POST_SIZE indicates the number of bytes that will make the POST
   data get included in the initial data chunk sent to the server. If the
   data is larger than this, it will automatically get split up in multiple
   system calls.

   This value used to be fairly big (100K), but we must take into account that
   if the server rejects the POST due for authentication reasons, this data
   will always be uncondtionally sent and thus it may not be larger than can
   always be afforded to send twice.

   It must not be greater than 64K to work on VMS.
*/
#ifndef MAX_INITIAL_POST_SIZE
#define MAX_INITIAL_POST_SIZE (64*1024)
#endif

#ifndef TINY_INITIAL_POST_SIZE
#define TINY_INITIAL_POST_SIZE 1024
#endif

#endif
#endif
