#ifndef HEADER_CURL_DFILTERS_H
#define HEADER_CURL_DFILTERS_H
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

#define DF_WRITE_BODY    (1<<0)
#define DF_WRITE_HEADER  (1<<1)
#define DF_WRITE_STATUS  (1<<2) /* the first "header" is the status line */
#define DF_WRITE_CONNECT (1<<3) /* a CONNECT response */
#define DF_WRITE_1XX     (1<<4) /* a 1xx response */
#define DF_WRITE_TRAILER (1<<5) /* a trailer header */
#define DF_WRITE_BOTH    (DF_WRITE_BODY|DF_WRITE_HEADER)


/* Data filter phases. Each data filter is added with a `phase` attribute
 * that determines where in the data filter chain it is inserted.
 *
 * For writers, these are ordered when added so that data passes like
 *    CONN -> TRANSCODE -> CONTENT -> APP
 * The phases intended use is as follows:
 * CONN       the data is passed unmodified as it has been received from
 *            the connection. Main use is monitoring of raw data, gathering
 *            statictics, etc.
 * TRANSCODE  the data is tranformed from its network presentation to its
 *            internal format. Examples would be HTTP de-chunking, FTP line
 *            end conversions, etc.
 * PROTOCOL   meta data can be inspected and acted upon
 * CONTENT    body data is decoded into its final form for the application.
 *            Examples: HTTP Conent-Encodings like gzip, brotli, etc.
 * APP        Delivery of data to the application. Also suitable for
 *            monitoring the "net" amount of data transferred.
 *
 * Writers in the same phase are called in reverse order of addition. E.g.
 * adding first "gzip" then "deflate" for CONTENT means that "deflate"
 * gets the data first, then passes the deflated bytes on to "gzip".
 */
typedef enum {
  CURL_DF_PHASE_CONN,
  CURL_DF_PHASE_TRANSCODE,
  CURL_DF_PHASE_CONTENT,
  CURL_DF_PHASE_APP,
} curl_df_phase;

/**
 * Structure allocated when adding a write filter.
 */
struct Curl_df_writer {
  const struct Curl_df_write_type *dft;  /* writer implementation */
  struct Curl_df_writer *next;  /* next writer in chain */
  void *ctx;                    /* implementation specific data */
  curl_df_phase phase;          /* determines ordering in write/read stacks */
};

/**
 * Data filter write type. Implements methods for initialization, writing
 * data and closing when done.
 * `writersize` needs to be at least `sizeof(struct Curl_df_writer)`. Using
 * more allows for writer specific struct overloads.
 */
struct Curl_df_write_type {
  const char *name;        /* filter name, MUST be set */
  const char *alias;       /* alternate name, may be NULL */
  CURLcode (*do_init)(struct Curl_df_writer *writer, struct Curl_easy *data);
  CURLcode (*do_meta)(struct Curl_df_writer *writer, struct Curl_easy *data,
                      int meta_type, const char *buf, size_t nbytes);
  CURLcode (*do_body)(struct Curl_df_writer *writer, struct Curl_easy *data,
                      const char *buf, size_t nbytes);
  void (*do_close)(struct Curl_df_writer *writer, struct Curl_easy *data);
  bool (*is_paused)(struct Curl_df_writer *writer, struct Curl_easy *data);
  CURLcode (*unpause)(struct Curl_df_writer *writer, struct Curl_easy *data);
  size_t writersize;
};


/**
 * Default implementations for writer types with no special handling
 */
CURLcode Curl_df_def_do_meta(struct Curl_df_writer *writer,
                             struct Curl_easy *data,
                             int meta_type, const char *buf, size_t nbytes);
CURLcode Curl_df_def_do_body(struct Curl_df_writer *writer,
                             struct Curl_easy *data,
                             const char *buf, size_t nbytes);
bool Curl_df_def_is_paused(struct Curl_df_writer *writer,
                           struct Curl_easy *data);
CURLcode Curl_df_def_unpause(struct Curl_df_writer *writer,
                             struct Curl_easy *data);

/**
 * Call the `do_body` method of write filter `df`. Does NULL parameter
 * checks and handles 0-length writes.
 * @param df writer instance to call, gives error return when NULL
 * @param data transfer this writer has been added to
 * @param buf  body data to write
 * @param blen amount of bytes in `buf`
 * @returns CURLE_OK or error, needs to handle all bytes on success
 */
CURLcode Curl_df_write_body(struct Curl_df_writer *df,
                            struct Curl_easy *data,
                            const char *buf, size_t blen);

/**
 * Call the `do_meta` method of write filter `df`. Does NULL parameter
 * checks and handles 0-length writes.
 * @param df writer instance to call, gives error return when NULL
 * @param data transfer this writer has been added to
 * @param meta_type  see CLIENTWRITE_* definitions in sendf.h
 * @param buf  meta data to write
 * @param blen amount of bytes in `buf`
 * @returns CURLE_OK or error, needs to handle all bytes on success
 */
CURLcode Curl_df_write_meta(struct Curl_df_writer *df,
                            struct Curl_easy *data, int meta_type,
                            const char *buf, size_t blen);

/**
 * Call the `is_paused` method of write filter `df`.
 * Does NULL parameter checks.
 */
bool Curl_df_is_paused(struct Curl_df_writer *df, struct Curl_easy *data);
/**
 * Call the `unpause` method of write filter `df`.
 * Does NULL parameter checks.
 */
CURLcode Curl_df_unpause(struct Curl_df_writer *df, struct Curl_easy *data);

/**
 * Cleanup, e.g. deallocate, all installed writers.
 * Calls writers `do_close` method.
 */
void Curl_df_writers_cleanup(struct Curl_easy *data);

/**
 * Add a writer to the transfer `data`in phase `phase`.
 * @param data  transfer to add the writer to
 * @param wtype writers implementation type
 * @param phase phase this writer is for
 * @param pwriter return added df instance, pass NULL of not interested
 */
CURLcode Curl_df_add_writer(struct Curl_easy *data,
                            const struct Curl_df_write_type *wtype,
                            curl_df_phase phase,
                            struct Curl_df_writer **pwriter);

/**
 * Write received BODY data to the client.
 * Applies installed df writers.
 * @param data       the transfer
 * @param buf        the bytes to write
 * @param blen       the amnount of bytes to write
 */
CURLcode Curl_client_write_body(struct Curl_easy *data,
                                char *buf, size_t blen);

/**
 * Write received META data of the given meta_type to the client.
 * Applies installed df writers.
 * @param data       the transfer
 * @param meta_type  see CLIENTWRITE_* definitions in sendf.h
 * @param buf        the bytes to write
 * @param blen       the amnount of bytes to write
 */
CURLcode Curl_client_write_meta(struct Curl_easy *data, int meta_type,
                                char *buf, size_t blen);

/**
 * Transfer has been unpaused and now is the time to write any
 * buffered client data that may have been kept back.
 */
CURLcode Curl_client_unpause(struct Curl_easy *data);

/**
 * @return TRUE iff there is paused, e.g. buffered data
 */
bool Curl_client_is_paused(struct Curl_easy *data);

#endif /* HEADER_CURL_DFILTERS_H */
