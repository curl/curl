#ifndef __SENDF_H
#define __SENDF_H
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

size_t Curl_sendf(int fd, struct UrlData *, char *fmt, ...);
size_t Curl_ssend(int fd, struct connectdata *, void *fmt, size_t len);
void Curl_infof(struct UrlData *, char *fmt, ...);
void Curl_failf(struct UrlData *, char *fmt, ...);

#define sendf Curl_sendf
#define ssend Curl_ssend
#define infof Curl_infof
#define failf Curl_failf

struct send_buffer {
  char *buffer;
  long size_max;
  long size_used;
};
typedef struct send_buffer send_buffer;

#define CLIENTWRITE_BODY   1
#define CLIENTWRITE_HEADER 2
#define CLIENTWRITE_BOTH   (CLIENTWRITE_BODY|CLIENTWRITE_HEADER)

CURLcode Curl_client_write(struct UrlData *data, int type, char *ptr,
                           size_t len);

#endif
