#ifndef __FTP_H
#define __FTP_H

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
CURLcode Curl_ftp(struct connectdata *conn);
CURLcode Curl_ftp_done(struct connectdata *conn);
CURLcode Curl_ftp_connect(struct connectdata *conn);

size_t Curl_ftpsendf(int fd, struct connectdata *, char *fmt, ...);

struct curl_slist *curl_slist_append(struct curl_slist *list, char *data);
void curl_slist_free_all(struct curl_slist *list);

/* The kerberos stuff needs this: */
int Curl_GetFTPResponse(int sockfd, char *buf,
                        struct connectdata *conn,
                        int *ftpcode);

#endif
