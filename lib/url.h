#ifndef __URL_H
#define __URL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include <stdarg.h> /* to make sure we have ap_list */

/*
 * Prototypes for library-wide functions provided by url.c
 */

CURLcode Curl_open(struct SessionHandle **curl);
CURLcode Curl_init_userdefined(struct UserDefined *set);
CURLcode Curl_setopt(struct SessionHandle *data, CURLoption option,
                     va_list arg);
CURLcode Curl_dupset(struct SessionHandle * dst, struct SessionHandle * src);
void Curl_freeset(struct SessionHandle * data);
CURLcode Curl_close(struct SessionHandle *data); /* opposite of curl_open() */
CURLcode Curl_connect(struct SessionHandle *, struct connectdata **,
                      bool *async, bool *protocol_connect);
CURLcode Curl_async_resolved(struct connectdata *conn,
                             bool *protocol_connect);
CURLcode Curl_do(struct connectdata **, bool *done);
CURLcode Curl_do_more(struct connectdata *);
CURLcode Curl_done(struct connectdata **, CURLcode, bool premature);
CURLcode Curl_disconnect(struct connectdata *);
CURLcode Curl_protocol_connect(struct connectdata *conn, bool *done);
CURLcode Curl_protocol_connecting(struct connectdata *conn, bool *done);
CURLcode Curl_protocol_doing(struct connectdata *conn, bool *done);
void Curl_safefree(void *ptr);

/* create a connection cache */
struct conncache *Curl_mk_connc(int type, long amount);
/* free a connection cache */
void Curl_rm_connc(struct conncache *c);
/* Change number of entries of a connection cache */
CURLcode Curl_ch_connc(struct SessionHandle *data,
                       struct conncache *c,
                       long newamount);

int Curl_protocol_getsock(struct connectdata *conn,
                          curl_socket_t *socks,
                          int numsocks);
int Curl_doing_getsock(struct connectdata *conn,
                       curl_socket_t *socks,
                       int numsocks);

bool Curl_isPipeliningEnabled(const struct SessionHandle *handle);
CURLcode Curl_addHandleToPipeline(struct SessionHandle *handle,
                                  struct curl_llist *pipeline);
int Curl_removeHandleFromPipeline(struct SessionHandle *handle,
                                  struct curl_llist *pipeline);
/* remove the specified connection from all (possible) pipelines and related
   queues */
void Curl_getoff_all_pipelines(struct SessionHandle *data,
                               struct connectdata *conn);

void Curl_close_connections(struct SessionHandle *data);

/* Called on connect, and if there's already a protocol-specific struct
   allocated for a different connection, this frees it that it can be setup
   properly later on. */
void Curl_reset_reqproto(struct connectdata *conn);

#define CURL_DEFAULT_PROXY_PORT 1080 /* default proxy port unless specified */
#define CURL_DEFAULT_SOCKS5_GSSAPI_SERVICE "rcmd" /* default socks5 gssapi service */

CURLcode Curl_connected_proxy(struct connectdata *conn);

#endif
