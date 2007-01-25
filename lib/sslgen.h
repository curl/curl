#ifndef __SSLGEN_H
#define __SSLGEN_H
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

bool Curl_ssl_config_matches(struct ssl_config_data* data,
                             struct ssl_config_data* needle);
bool Curl_clone_ssl_config(struct ssl_config_data* source,
                           struct ssl_config_data* dest);
void Curl_free_ssl_config(struct ssl_config_data* sslc);

int Curl_ssl_init(void);
void Curl_ssl_cleanup(void);
CURLcode Curl_ssl_connect(struct connectdata *conn, int sockindex);
CURLcode Curl_ssl_connect_nonblocking(struct connectdata *conn,
                                      int sockindex,
                                      bool *done);
void Curl_ssl_close(struct connectdata *conn);
/* tell the SSL stuff to close down all open information regarding
   connections (and thus session ID caching etc) */
void Curl_ssl_close_all(struct SessionHandle *data);
CURLcode Curl_ssl_set_engine(struct SessionHandle *data, const char *engine);
/* Sets engine as default for all SSL operations */
CURLcode Curl_ssl_set_engine_default(struct SessionHandle *data);
ssize_t Curl_ssl_send(struct connectdata *conn,
                      int sockindex,
                      void *mem,
                      size_t len);
ssize_t Curl_ssl_recv(struct connectdata *conn, /* connection data */
                      int sockindex,            /* socketindex */
                      char *mem,                /* store read data here */
                      size_t len);              /* max amount to read */

/* init the SSL session ID cache */
CURLcode Curl_ssl_initsessions(struct SessionHandle *, long);
/* extract a session ID */
int Curl_ssl_getsessionid(struct connectdata *conn,
                          void **ssl_sessionid,
                          size_t *idsize) /* set 0 if unknown */;
/* add a new session ID */
CURLcode Curl_ssl_addsessionid(struct connectdata *conn,
                               void *ssl_sessionid,
                               size_t idsize);


struct curl_slist *Curl_ssl_engines_list(struct SessionHandle *data);

size_t Curl_ssl_version(char *buffer, size_t size);

int Curl_ssl_check_cxn(struct connectdata *conn);

CURLcode Curl_ssl_shutdown(struct connectdata *conn, int sockindex);

bool Curl_ssl_data_pending(struct connectdata *conn,
                           int connindex);

#if !defined(USE_SSL) && !defined(SSLGEN_C)
/* set up blank macros for none-SSL builds */
#define Curl_ssl_close_all(x)
#endif

#define SSL_SHUTDOWN_TIMEOUT 10000 /* ms */

#endif
