#ifndef __SSH_H
#define __SSH_H

/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_LIBSSH2
extern const struct Curl_handler Curl_handler_scp;
extern const struct Curl_handler Curl_handler_sftp;

ssize_t Curl_scp_send(struct connectdata *conn, int sockindex,
                      const void *mem, size_t len);
ssize_t Curl_scp_recv(struct connectdata *conn, int sockindex,
                      char *mem, size_t len);

ssize_t Curl_sftp_send(struct connectdata *conn, int sockindex,
                       const void *mem, size_t len);
ssize_t Curl_sftp_recv(struct connectdata *conn, int sockindex,
                       char *mem, size_t len);

#define Curl_ssh_enabled(conn,prot) (conn->protocol & prot)

#else /* USE_LIBSSH2 */
#define Curl_ssh_enabled(x,y) 0
#define Curl_scp_send(a,b,c,d) 0
#define Curl_sftp_send(a,b,c,d) 0
#define Curl_scp_recv(a,b,c,d) 0
#define Curl_sftp_recv(a,b,c,d) 0

#endif /* USE_LIBSSH2 */

#endif /* __SSH_H */
