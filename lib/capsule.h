#ifndef HEADER_CURL_CAPSULE_H
#define HEADER_CURL_CAPSULE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP) && \
    defined(USE_NGHTTP3) && defined(USE_OPENSSL_QUIC)

#include <openssl/bio.h>
#include "curlx/dynbuf.h"
#include "bufq.h"

/* HTTP Capsule constants */
#define HTTP_INVALID_VARINT             ((uint64_t) ~0)
#define HTTP_CAPSULE_HEADER_MAX_SIZE    10

/* HTTP Capsule types */
#define foreach_http_capsule_type _ (0, DATAGRAM)
typedef enum http_capsule_type_
{
#define _(n, s) HTTP_CAPSULE_TYPE_##s = n,
  foreach_http_capsule_type
#undef _
} __attribute__((packed)) http_capsule_type_t;

/* BIO_MSG helper macro */
#define BIO_MSG_N(array, stride, n) \
  (*(BIO_MSG *)((char *)(array) + (n)*(stride)))

/* HTTP Capsule function prototypes */

/**
 * Encapsulate UDP payload into HTTP Datagram capsule format
 * @param dyn   Dynamic buffer to write capsule to
 * @param buf   Payload buffer
 * @param blen  Payload buffer length
 * @return CURLE_OK on success, error code on failure
 */
CURLcode Curl_capsule_encap_udp_datagram(struct dynbuf *dyn,
                                         const void *buf, size_t blen);

/**
 * Process UDP capsules from buffer into BIO_MSG structures
 * @param cf        Connection filter
 * @param data      Easy handle
 * @param recvbufq  Buffer queue containing capsule data
 * @param buf       Output buffer (array of BIO_MSG structures)
 * @param len       Size/stride of BIO_MSG structures
 * @param err       Error code output
 * @return Number of messages processed, or -1 on error
 */
size_t Curl_capsule_process_udp(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct bufq *recvbufq,
                                 char *buf, size_t len, CURLcode *err);

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP &&
                USE_NGHTTP3 && USE_OPENSSL_QUIC */

#endif /* HEADER_CURL_CAPSULE_H */
