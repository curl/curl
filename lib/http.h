#ifndef __HTTP_H
#define __HTTP_H

/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

/* ftp can use this as well */
CURLcode Curl_ConnectHTTPProxyTunnel(struct UrlData *data, int tunnelsocket,
                                     char *hostname, int remote_port);

/* protocol-specific functions set up to be called by the main engine */
CURLcode Curl_http(struct connectdata *conn);
CURLcode Curl_http_done(struct connectdata *conn);
CURLcode Curl_http_connect(struct connectdata *conn);
CURLcode Curl_http_close(struct connectdata *conn);

#endif
