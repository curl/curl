#ifndef HEADER_CURL_VQUIC_QUICHE_H
#define HEADER_CURL_VQUIC_QUICHE_H
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

#ifdef USE_QUICHE

#include <quiche.h>
#include <openssl/ssl.h>

struct quic_handshake {
  char *buf;       /* pointer to the buffer */
  size_t alloclen; /* size of allocation */
  size_t len;      /* size of content in buffer */
  size_t nread;    /* how many bytes have been read */
};

struct quicsocket {
  quiche_config *cfg;
  quiche_conn *conn;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  curl_socket_t sockfd;
  uint32_t version;
  SSL_CTX *sslctx;
  SSL *ssl;
  bool h3_recving; /* TRUE when in h3-body-reading state */
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
};

#endif

#endif /* HEADER_CURL_VQUIC_QUICHE_H */
