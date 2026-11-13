#ifndef HEADER_CURL_DYNHDS_H
#define HEADER_CURL_DYNHDS_H
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

#include "curlx/dynbuf.h"

struct dynbuf;
struct curl_slist;
struct Curl_str;

/* A single header entry.
 * `name` and `value` are non-NULL and always null-terminated. */
struct dynhds_entry {
  char *name;
  char *value;
  uint32_t namelen;
  uint32_t valuelen;
};

struct dynhds {
  struct dynhds_entry **hds;
  uint32_t hds_len;   /* number of entries in hds */
  uint32_t hds_allc;  /* size of hds allocation */
  uint32_t max_entries;   /* size limit number of entries */
  uint32_t strs_len; /* length of all strings */
  uint32_t max_strs_size; /* max length of all strings */
  uint8_t opts;
};

#define DYNHDS_OPT_NONE          0U
#define DYNHDS_OPT_LOWERCASE     (1U << 0)

/* Init for use on first time or after a reset/cleanup.
 * Allow `max_entries` headers to be added, 0 for UINT32_MAX.
 * Allow size of all name and values added to not exceed `max_strs_size`,
 * 0 for UINT32_MAX. */
void Curl_dynhds_init(struct dynhds *dynhds, uint32_t max_entries,
                      uint32_t max_strs_size);

/* Frees all data held in `dynhds`, but not the struct itself. */
void Curl_dynhds_cleanup(struct dynhds *dynhds);

/* Reset `dyndns` to the initial init state. May keep allocations around. */
void Curl_dynhds_reset(struct dynhds *dynhds);

/* Return the number of header entries. */
uint32_t Curl_dynhds_count(struct dynhds *dynhds);

/* Set the options to use, replacing any existing ones.
 * This will not have an effect on already existing headers. */
void Curl_dynhds_set_opts(struct dynhds *dynhds, uint8_t opts);

/* Return the n-th header entry or NULL if it does not exist. */
struct dynhds_entry *Curl_dynhds_getn(struct dynhds *dynhds, uint32_t n);

/* Return the 1st header entry of the name or NULL if none exists. */
struct dynhds_entry *Curl_dynhds_get(struct dynhds *dynhds,
                                     const char *name, size_t namelen);
struct dynhds_entry *Curl_dynhds_cget(struct dynhds *dynhds, const char *name);

CURLcode Curl_dynhds_cset(struct dynhds *dynhds,
                          const char *name, const char *value);

/* Add a header, name + value, to `dynhds` at the end. Does *not*
 * check for duplicate names. */
CURLcode Curl_dynhds_add(struct dynhds *dynhds,
                         const char *name, size_t namelen,
                         const char *value, size_t valuelen);

/* Add a header, c-string name + value, to `dynhds` at the end. */
CURLcode Curl_dynhds_cadd(struct dynhds *dynhds,
                          const char *name, const char *value);

/* Add a single header from an HTTP/1.1 formatted line at the end. Line may
 * contain a delimiting CRLF or LF. Any chars after that will be ignored. */
CURLcode Curl_dynhds_h1_cadd_line(struct dynhds *dynhds, const char *line);

/* Add a single header from an HTTP/1.1 formatted line at the end. Line may
 * contain a delimiting CRLF or LF. Any chars after that will be ignored. */
CURLcode Curl_dynhds_h1_add_line(struct dynhds *dynhds,
                                 const char *line, size_t line_len);

/* Add the headers to the given `dynbuf` in HTTP/1.1 format with
 * CR+LF line endings. Does NOT output a last empty line. */
CURLcode Curl_dynhds_h1_dprint(struct dynhds *dynhds, struct dynbuf *dbuf);

/* Return CURLE_OK to have header further processed.
 * Return CURLE_AGAIN to have header pair ignored.
 * Other values indicate a fatal error */
typedef CURLcode Curl_dynhds_hd_cb(void *user_data,
                                   struct Curl_str *name,
                                   struct Curl_str *value,
                                   const char *orig_data);

/* Add headers form an slist with semantics from CURLOPT_HTTPHEADER.
 * Provide an optional ignore_cb to prevent headers from being added.
 * May be called with dynhds == NULL to just parse and invoked callback. */
CURLcode Curl_dynhds_add_slist(struct dynhds *dynhds,
                               struct curl_slist *headers,
                               Curl_dynhds_hd_cb *hd_cb,
                               void *user_data);

#ifdef USE_NGHTTP2

#include <nghttp2/nghttp2.h>

nghttp2_nv *Curl_dynhds_to_nva(struct dynhds *dynhds, size_t *pcount);

#endif /* USE_NGHTTP2 */

#endif /* HEADER_CURL_DYNHDS_H */
