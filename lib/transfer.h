#ifndef __TRANSFER_H
#define __TRANSFER_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
CURLcode Curl_perform(struct SessionHandle *data);
CURLcode Curl_pretransfer(struct SessionHandle *data);
CURLcode Curl_second_connect(struct connectdata *conn);
CURLcode Curl_posttransfer(struct SessionHandle *data);
CURLcode Curl_follow(struct SessionHandle *data, char *newurl, bool retry);
CURLcode Curl_readwrite(struct connectdata *conn, bool *done);
int Curl_single_getsock(struct connectdata *conn,
                        curl_socket_t *socks,
                        int numsocks);
CURLcode Curl_readwrite_init(struct connectdata *conn);
CURLcode Curl_readrewind(struct connectdata *conn);
CURLcode Curl_fillreadbuffer(struct connectdata *conn, int bytes, int *nreadp);
bool Curl_retry_request(struct connectdata *conn, char **url);

/* This sets up a forthcoming transfer */
CURLcode
Curl_setup_transfer (struct connectdata *data,
               int sockindex,           /* socket index to read from or -1 */
               curl_off_t size,         /* -1 if unknown at this point */
               bool getheader,          /* TRUE if header parsing is wanted */
               curl_off_t *bytecountp,  /* return number of bytes read */
               int writesockindex,      /* socket index to write to, it may
                                           very well be the same we read from.
                                           -1 disables */
               curl_off_t *writecountp /* return number of bytes written */
);
#endif
