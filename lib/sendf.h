#ifndef HEADER_CURL_SENDF_H
#define HEADER_CURL_SENDF_H
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

#include "curl_trc.h"

/**
 * Type of data that is being written to the client (application)
 * - data written can be either BODY or META data
 * - META data is either INFO or HEADER
 * - INFO is meta information, e.g. not BODY, that cannot be interpreted
 *   as headers of a response. Example FTP/IMAP pingpong answers.
 * - HEADER can have additional bits set (more than one)
 *   - STATUS special "header", e.g. response status line in HTTP
 *   - CONNECT header was received during proxying the connection
 *   - 1XX header is part of an intermediate response, e.g. HTTP 1xx code
 *   - TRAILER header is trailing response data, e.g. HTTP trailers
 * BODY, INFO and HEADER should not be mixed, as this would lead to
 * confusion on how to interpret/format/convert the data.
 */
#define CLIENTWRITE_BODY    (1<<0) /* non-meta information, BODY */
#define CLIENTWRITE_INFO    (1<<1) /* meta information, not a HEADER */
#define CLIENTWRITE_HEADER  (1<<2) /* meta information, HEADER */
#define CLIENTWRITE_STATUS  (1<<3) /* a special status HEADER */
#define CLIENTWRITE_CONNECT (1<<4) /* a CONNECT related HEADER */
#define CLIENTWRITE_1XX     (1<<5) /* a 1xx response related HEADER */
#define CLIENTWRITE_TRAILER (1<<6) /* a trailer HEADER */

CURLcode Curl_client_write(struct Curl_easy *data, int type, char *ptr,
                           size_t len) WARN_UNUSED_RESULT;

CURLcode Curl_client_unpause(struct Curl_easy *data);
void Curl_client_cleanup(struct Curl_easy *data);

struct contenc_writer {
  const struct content_encoding *handler;  /* Encoding handler. */
  struct contenc_writer *downstream;  /* Downstream writer. */
  unsigned int order; /* Ordering within writer stack. */
};

/* Content encoding writer. */
struct content_encoding {
  const char *name;        /* Encoding name. */
  const char *alias;       /* Encoding name alias. */
  CURLcode (*init_writer)(struct Curl_easy *data,
                          struct contenc_writer *writer);
  CURLcode (*unencode_write)(struct Curl_easy *data,
                             struct contenc_writer *writer,
                             const char *buf, size_t nbytes);
  void (*close_writer)(struct Curl_easy *data,
                       struct contenc_writer *writer);
  size_t writersize;
};


CURLcode Curl_client_create_writer(struct contenc_writer **pwriter,
                                   struct Curl_easy *data,
                                   const struct content_encoding *ce_handler,
                                   int order);

void Curl_client_free_writer(struct Curl_easy *data,
                             struct contenc_writer *writer);

CURLcode Curl_client_add_writer(struct Curl_easy *data,
                                struct contenc_writer *writer);


/* internal read-function, does plain socket, SSL and krb4 */
CURLcode Curl_read(struct Curl_easy *data, curl_socket_t sockfd,
                   char *buf, size_t buffersize,
                   ssize_t *n);

/* internal write-function, does plain socket, SSL, SCP, SFTP and krb4 */
CURLcode Curl_write(struct Curl_easy *data,
                    curl_socket_t sockfd,
                    const void *mem, size_t len,
                    ssize_t *written);

/* internal write-function, using sockindex for connection destination */
CURLcode Curl_nwrite(struct Curl_easy *data,
                     int sockindex,
                     const void *buf,
                     size_t blen,
                     ssize_t *pnwritten);

#endif /* HEADER_CURL_SENDF_H */
