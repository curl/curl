#ifndef __HTTP_H
#define __HTTP_H

/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* ftp can use this as well */
CURLcode Curl_ConnectHTTPProxyTunnel(struct connectdata *conn,
                                     int tunnelsocket,
                                     char *hostname, int remote_port);

/* protocol-specific functions set up to be called by the main engine */
CURLcode Curl_http(struct connectdata *conn);
CURLcode Curl_http_done(struct connectdata *conn);
CURLcode Curl_http_connect(struct connectdata *conn);

/* The following functions are defined in http_chunks.c */
void Curl_httpchunk_init(struct connectdata *conn);
CHUNKcode Curl_httpchunk_read(struct connectdata *conn, char *datap,
                              ssize_t length, ssize_t *wrote);
#endif
#endif
