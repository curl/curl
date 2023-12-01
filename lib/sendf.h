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
#define CLIENTWRITE_EOS     (1<<7) /* End Of transfer download Stream */

/**
 * Write `len` bytes at `prt` to the client. `type` indicates what
 * kind of data is being written.
 */
CURLcode Curl_client_write(struct Curl_easy *data, int type, char *ptr,
                           size_t len) WARN_UNUSED_RESULT;

/**
 * For a paused transfer, there might be buffered data held back.
 * Attempt to flush this data to the client. This *may* trigger
 * another pause of the transfer.
 */
CURLcode Curl_client_unpause(struct Curl_easy *data);

/**
 * Free all resources related to client writing.
 */
void Curl_client_cleanup(struct Curl_easy *data);

/**
 * Client Writers - a chain passing transfer BODY data to the client.
 * Main application: HTTP and related protocols
 * Other uses: monitoring of download progress
 *
 * Writers in the chain are order by their `phase`. First come all
 * writers in CURL_CW_RAW, followed by any in CURL_CW_TRANSFER_DECODE,
 * followed by any in CURL_CW_PROTOCOL, etc.
 *
 * When adding a writer, it is inserted as first in its phase. This means
 * the order of adding writers of the same phase matters, but writers for
 * different phases may be added in any order.
 *
 * Writers which do modify the BODY data written are expected to be of
 * phases TRANSFER_DECODE or CONTENT_DECODE. The other phases are intended
 * for monitoring writers. Which do *not* modify the data but gather
 * statistics or update progress reporting.
 */

/* Phase a writer operates at. */
typedef enum {
  CURL_CW_RAW,  /* raw data written, before any decoding */
  CURL_CW_TRANSFER_DECODE, /* remove transfer-encodings */
  CURL_CW_PROTOCOL, /* after transfer, but before content decoding */
  CURL_CW_CONTENT_DECODE, /* remove content-encodings */
  CURL_CW_CLIENT  /* data written to client */
} Curl_cwriter_phase;

/* Client Writer Type, provides the implementation */
struct Curl_cwtype {
  const char *name;        /* writer name. */
  const char *alias;       /* writer name alias, maybe NULL. */
  CURLcode (*do_init)(struct Curl_easy *data,
                      struct Curl_cwriter *writer);
  CURLcode (*do_write)(struct Curl_easy *data,
                       struct Curl_cwriter *writer, int type,
                       const char *buf, size_t nbytes);
  void (*do_close)(struct Curl_easy *data,
                   struct Curl_cwriter *writer);
  size_t cwriter_size;  /* sizeof() allocated struct Curl_cwriter */
};

/* Client writer instance */
struct Curl_cwriter {
  const struct Curl_cwtype *cwt;  /* type implementation */
  struct Curl_cwriter *next;  /* Downstream writer. */
  Curl_cwriter_phase phase; /* phase at which it operates */
};

/**
 * Create a new cwriter instance with given type and phase. Is not
 * inserted into the writer chain by this call.
 * Invokes `writer->do_init()`.
 */
CURLcode Curl_cwriter_create(struct Curl_cwriter **pwriter,
                             struct Curl_easy *data,
                             const struct Curl_cwtype *ce_handler,
                             Curl_cwriter_phase phase);

/**
 * Free a cwriter instance.
 * Invokes `writer->do_close()`.
 */
void Curl_cwriter_free(struct Curl_easy *data,
                       struct Curl_cwriter *writer);

/**
 * Count the number of writers installed of the given phase.
 */
size_t Curl_cwriter_count(struct Curl_easy *data, Curl_cwriter_phase phase);

/**
 * Adds a writer to the transfer's writer chain.
 * The writers `phase` determines where in the chain it is inserted.
 */
CURLcode Curl_cwriter_add(struct Curl_easy *data,
                          struct Curl_cwriter *writer);

void Curl_cwriter_remove_by_name(struct Curl_easy *data,
                                 const char *name);

/**
 * Convenience method for calling `writer->do_write()` that
 * checks for NULL writer.
 */
CURLcode Curl_cwriter_write(struct Curl_easy *data,
                            struct Curl_cwriter *writer, int type,
                            const char *buf, size_t nbytes);

/**
 * Default implementations for do_init, do_write, do_close that
 * do nothing and pass the data through.
 */
CURLcode Curl_cwriter_def_init(struct Curl_easy *data,
                               struct Curl_cwriter *writer);
CURLcode Curl_cwriter_def_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t nbytes);
void Curl_cwriter_def_close(struct Curl_easy *data,
                            struct Curl_cwriter *writer);


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
