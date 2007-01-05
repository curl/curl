#ifndef __GTLS_H
#define __GTLS_H
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
int Curl_gtls_init(void);
int Curl_gtls_cleanup(void);
CURLcode Curl_gtls_connect(struct connectdata *conn, int sockindex);

/* tell GnuTLS to close down all open information regarding connections (and
   thus session ID caching etc) */
void Curl_gtls_close_all(struct SessionHandle *data);
void Curl_gtls_close(struct connectdata *conn); /* close a SSL connection */

/* return number of sent (non-SSL) bytes */
ssize_t Curl_gtls_send(struct connectdata *conn, int sockindex,
                       void *mem, size_t len);
ssize_t Curl_gtls_recv(struct connectdata *conn, /* connection data */
                       int num,                  /* socketindex */
                       char *buf,                /* store read data here */
                       size_t buffersize,        /* max amount to read */
                       bool *wouldblock);
void Curl_gtls_session_free(void *ptr);
size_t Curl_gtls_version(char *buffer, size_t size);
int Curl_gtls_shutdown(struct connectdata *conn, int sockindex);

#endif
