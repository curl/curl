#ifndef HEADER_CURL_VTLS_INT_H
#define HEADER_CURL_VTLS_INT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"
#include "urldata.h"

/* Definitions for SSL Implementations */

 struct Curl_ssl {
  /*
   * This *must* be the first entry to allow returning the list of available
   * backends in curl_global_sslset().
   */
  curl_ssl_backend info;
  unsigned int supports; /* bitfield, see above */
  size_t sizeof_ssl_backend_data;

  int (*init)(void);
  void (*cleanup)(void);

  size_t (*version)(char *buffer, size_t size);
  int (*check_cxn)(struct connectdata *cxn);
  int (*shut_down)(struct Curl_easy *data, struct connectdata *conn,
                   int sockindex);
  bool (*data_pending)(const struct connectdata *conn,
                       int connindex);

  /* return 0 if a find random is filled in */
  CURLcode (*random)(struct Curl_easy *data, unsigned char *entropy,
                     size_t length);
  bool (*cert_status_request)(void);

  CURLcode (*connect_blocking)(struct Curl_easy *data,
                               struct connectdata *conn, int sockindex);
  CURLcode (*connect_nonblocking)(struct Curl_easy *data,
                                  struct connectdata *conn, int sockindex,
                                  bool *done);

  /* If the SSL backend wants to read or write on this connection during a
     handshake, set socks[0] to the connection's FIRSTSOCKET, and return
     a bitmap indicating read or write with GETSOCK_WRITESOCK(0) or
     GETSOCK_READSOCK(0). Otherwise return GETSOCK_BLANK.
     Mandatory. */
  int (*getsock)(struct connectdata *conn, curl_socket_t *socks);

  void *(*get_internals)(struct ssl_connect_data *connssl, CURLINFO info);
  void (*close_one)(struct Curl_easy *data, struct connectdata *conn,
                    int sockindex);
  void (*close_all)(struct Curl_easy *data);
  void (*session_free)(void *ptr);

  CURLcode (*set_engine)(struct Curl_easy *data, const char *engine);
  CURLcode (*set_engine_default)(struct Curl_easy *data);
  struct curl_slist *(*engines_list)(struct Curl_easy *data);

  bool (*false_start)(void);
  CURLcode (*sha256sum)(const unsigned char *input, size_t inputlen,
                    unsigned char *sha256sum, size_t sha256sumlen);

  bool (*associate_connection)(struct Curl_easy *data,
                               struct connectdata *conn,
                               int sockindex);
  void (*disassociate_connection)(struct Curl_easy *data, int sockindex);

  void (*free_multi_ssl_backend_data)(struct multi_ssl_backend_data *mbackend);

  ssize_t (*recv_plain)(struct Curl_easy *data, int sockindex, char *buf,
                        size_t len, CURLcode *code);
  ssize_t (*send_plain)(struct Curl_easy *data, int sockindex,
                        const void *mem, size_t len, CURLcode *code);

};

extern const struct Curl_ssl *Curl_ssl;


int Curl_none_init(void);
void Curl_none_cleanup(void);
int Curl_none_shutdown(struct Curl_easy *data, struct connectdata *conn,
                       int sockindex);
int Curl_none_check_cxn(struct connectdata *conn);
CURLcode Curl_none_random(struct Curl_easy *data, unsigned char *entropy,
                          size_t length);
void Curl_none_close_all(struct Curl_easy *data);
void Curl_none_session_free(void *ptr);
bool Curl_none_data_pending(const struct connectdata *conn, int connindex);
bool Curl_none_cert_status_request(void);
CURLcode Curl_none_set_engine(struct Curl_easy *data, const char *engine);
CURLcode Curl_none_set_engine_default(struct Curl_easy *data);
struct curl_slist *Curl_none_engines_list(struct Curl_easy *data);
bool Curl_none_false_start(void);
int Curl_ssl_getsock(struct connectdata *conn, curl_socket_t *socks);

#include "openssl.h"        /* OpenSSL versions */
#include "gtls.h"           /* GnuTLS versions */
#include "nssg.h"           /* NSS versions */
#include "gskit.h"          /* Global Secure ToolKit versions */
#include "wolfssl.h"        /* wolfSSL versions */
#include "schannel.h"       /* Schannel SSPI version */
#include "sectransp.h"      /* SecureTransport (Darwin) version */
#include "mbedtls.h"        /* mbedTLS versions */
#include "bearssl.h"        /* BearSSL versions */
#include "rustls.h"         /* rustls versions */

#endif /* HEADER_CURL_VTLS_INT_H */
