#ifndef HEADER_CURL_URL_H
#define HEADER_CURL_URL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"

/*
 * Prototypes for library-wide functions provided by url.c
 */

CURLcode Curl_init_do(struct Curl_easy *data, struct connectdata *conn);
CURLcode Curl_open(struct Curl_easy **curl);
CURLcode Curl_init_userdefined(struct UserDefined *set);
CURLcode Curl_setopt(struct Curl_easy *data, CURLoption option,
                     va_list arg);
CURLcode Curl_dupset(struct Curl_easy * dst, struct Curl_easy * src);
void Curl_freeset(struct Curl_easy * data);
CURLcode Curl_close(struct Curl_easy *data); /* opposite of curl_open() */
CURLcode Curl_connect(struct Curl_easy *, struct connectdata **,
                      bool *async, bool *protocol_connect);
CURLcode Curl_disconnect(struct connectdata *, bool dead_connection);
CURLcode Curl_protocol_connect(struct connectdata *conn, bool *done);
CURLcode Curl_protocol_connecting(struct connectdata *conn, bool *done);
CURLcode Curl_protocol_doing(struct connectdata *conn, bool *done);
CURLcode Curl_setup_conn(struct connectdata *conn,
                         bool *protocol_done);
void Curl_free_request_state(struct Curl_easy *data);

int Curl_protocol_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks);
int Curl_doing_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks);

bool Curl_isPipeliningEnabled(const struct Curl_easy *handle);
CURLcode Curl_addHandleToPipeline(struct Curl_easy *handle,
                                  struct curl_llist *pipeline);
int Curl_removeHandleFromPipeline(struct Curl_easy *handle,
                                  struct curl_llist *pipeline);
struct connectdata *
Curl_oldest_idle_connection(struct Curl_easy *data);
/* remove the specified connection from all (possible) pipelines and related
   queues */
void Curl_getoff_all_pipelines(struct Curl_easy *data,
                               struct connectdata *conn);

void Curl_close_connections(struct Curl_easy *data);

#define CURL_DEFAULT_PROXY_PORT 1080 /* default proxy port unless specified */

CURLcode Curl_connected_proxy(struct connectdata *conn, int sockindex);

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define Curl_verboseconnect(x)  Curl_nop_stmt
#else
void Curl_verboseconnect(struct connectdata *conn);
#endif


#endif /* HEADER_CURL_URL_H */
