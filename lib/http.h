#ifndef HEADER_FETCH_HTTP_H
#define HEADER_FETCH_HTTP_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetch_setup.h"

#if defined(USE_MSH3) && !defined(_WIN32)
#include <pthread.h>
#endif

#include "bufq.h"
#include "dynhds.h"
#include "ws.h"

typedef enum
{
  HTTPREQ_GET,
  HTTPREQ_POST,
  HTTPREQ_POST_FORM, /* we make a difference internally */
  HTTPREQ_POST_MIME, /* we make a difference internally */
  HTTPREQ_PUT,
  HTTPREQ_HEAD
} Fetch_HttpReq;

/* When redirecting transfers. */
typedef enum
{
  FOLLOW_NONE,  /* not used within the function, just a placeholder to
                   allow initing to this */
  FOLLOW_FAKE,  /* only records stuff, not actually following */
  FOLLOW_RETRY, /* set if this is a request retry as opposed to a real
                   redirect following */
  FOLLOW_REDIR  /* a full true redirect */
} followtype;

#ifndef FETCH_DISABLE_HTTP

#if defined(USE_HTTP3)
#include <stdint.h>
#endif

extern const struct Fetch_handler Fetch_handler_http;

#ifdef USE_SSL
extern const struct Fetch_handler Fetch_handler_https;
#endif

struct dynhds;

FETCHcode Fetch_bump_headersize(struct Fetch_easy *data,
                               size_t delta,
                               bool connect_only);

/* Header specific functions */
bool Fetch_compareheader(const char *headerline, /* line to check */
                        const char *header,     /* header keyword _with_ colon */
                        const size_t hlen,      /* len of the keyword in bytes */
                        const char *content,    /* content string to find */
                        const size_t clen);     /* len of the content in bytes */

char *Fetch_copy_header_value(const char *header);

char *Fetch_checkProxyheaders(struct Fetch_easy *data,
                             const struct connectdata *conn,
                             const char *thisheader,
                             const size_t thislen);

FETCHcode Fetch_add_timecondition(struct Fetch_easy *data, struct dynbuf *req);
FETCHcode Fetch_add_custom_headers(struct Fetch_easy *data, bool is_connect,
                                  int httpversion, struct dynbuf *req);
FETCHcode Fetch_dynhds_add_custom(struct Fetch_easy *data, bool is_connect,
                                 struct dynhds *hds);

void Fetch_http_method(struct Fetch_easy *data, struct connectdata *conn,
                      const char **method, Fetch_HttpReq *);

/* protocol-specific functions set up to be called by the main engine */
FETCHcode Fetch_http_setup_conn(struct Fetch_easy *data,
                               struct connectdata *conn);
FETCHcode Fetch_http(struct Fetch_easy *data, bool *done);
FETCHcode Fetch_http_done(struct Fetch_easy *data, FETCHcode, bool premature);
FETCHcode Fetch_http_connect(struct Fetch_easy *data, bool *done);
int Fetch_http_getsock_do(struct Fetch_easy *data, struct connectdata *conn,
                         fetch_socket_t *socks);
FETCHcode Fetch_http_write_resp(struct Fetch_easy *data,
                               const char *buf, size_t blen,
                               bool is_eos);
FETCHcode Fetch_http_write_resp_hd(struct Fetch_easy *data,
                                  const char *hd, size_t hdlen,
                                  bool is_eos);

/* These functions are in http.c */
FETCHcode Fetch_http_input_auth(struct Fetch_easy *data, bool proxy,
                               const char *auth);
FETCHcode Fetch_http_auth_act(struct Fetch_easy *data);

/* follow a redirect or not */
FETCHcode Fetch_http_follow(struct Fetch_easy *data, const char *newurl,
                           followtype type);

/* If only the PICKNONE bit is set, there has been a round-trip and we
   selected to use no auth at all. Ie, we actively select no auth, as opposed
   to not having one selected. The other FETCHAUTH_* defines are present in the
   public fetch/fetch.h header. */
#define FETCHAUTH_PICKNONE (1 << 30) /* do not use auth */

/* MAX_INITIAL_POST_SIZE indicates the number of bytes that will make the POST
   data get included in the initial data chunk sent to the server. If the
   data is larger than this, it will automatically get split up in multiple
   system calls.

   This value used to be fairly big (100K), but we must take into account that
   if the server rejects the POST due for authentication reasons, this data
   will always be unconditionally sent and thus it may not be larger than can
   always be afforded to send twice.

   It must not be greater than 64K to work on VMS.
*/
#ifndef MAX_INITIAL_POST_SIZE
#define MAX_INITIAL_POST_SIZE (64 * 1024)
#endif

/* EXPECT_100_THRESHOLD is the request body size limit for when libfetch will
 * automatically add an "Expect: 100-continue" header in HTTP requests. When
 * the size is unknown, it will always add it.
 *
 */
#ifndef EXPECT_100_THRESHOLD
#define EXPECT_100_THRESHOLD (1024 * 1024)
#endif

/* MAX_HTTP_RESP_HEADER_SIZE is the maximum size of all response headers
   combined that libfetch allows for a single HTTP response, any HTTP
   version. This count includes CONNECT response headers. */
#define MAX_HTTP_RESP_HEADER_SIZE (300 * 1024)

#endif /* FETCH_DISABLE_HTTP */

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/

FETCHcode Fetch_http_write_resp_hds(struct Fetch_easy *data,
                                   const char *buf, size_t blen,
                                   size_t *pconsumed);

/**
 * Fetch_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. data->state.authdone is set to TRUE when authentication is
 * done.
 *
 * @param data all information about the current transfer
 * @param conn all information about the current connection
 * @param request pointer to the request keyword
 * @param httpreq is the request type
 * @param path pointer to the requested path
 * @param proxytunnel boolean if this is the request setting up a "proxy
 * tunnel"
 *
 * @returns FETCHcode
 */
FETCHcode
Fetch_http_output_auth(struct Fetch_easy *data,
                      struct connectdata *conn,
                      const char *request,
                      Fetch_HttpReq httpreq,
                      const char *path,
                      bool proxytunnel); /* TRUE if this is the request setting
                                            up the proxy tunnel */

/* Decode HTTP status code string. */
FETCHcode Fetch_http_decode_status(int *pstatus, const char *s, size_t len);

/**
 * All about a core HTTP request, excluding body and trailers
 */
struct httpreq
{
  char method[24];
  char *scheme;
  char *authority;
  char *path;
  struct dynhds headers;
  struct dynhds trailers;
};

/**
 * Create an HTTP request struct.
 */
FETCHcode Fetch_http_req_make(struct httpreq **preq,
                             const char *method, size_t m_len,
                             const char *scheme, size_t s_len,
                             const char *authority, size_t a_len,
                             const char *path, size_t p_len);

FETCHcode Fetch_http_req_make2(struct httpreq **preq,
                              const char *method, size_t m_len,
                              FETCHU *url, const char *scheme_default);

void Fetch_http_req_free(struct httpreq *req);

#define HTTP_PSEUDO_METHOD ":method"
#define HTTP_PSEUDO_SCHEME ":scheme"
#define HTTP_PSEUDO_AUTHORITY ":authority"
#define HTTP_PSEUDO_PATH ":path"
#define HTTP_PSEUDO_STATUS ":status"

/**
 * Create the list of HTTP/2 headers which represent the request,
 * using HTTP/2 pseudo headers preceding the `req->headers`.
 *
 * Applies the following transformations:
 * - if `authority` is set, any "Host" header is removed.
 * - if `authority` is unset and a "Host" header is present, use
 *   that as `authority` and remove "Host"
 * - removes and Connection header fields as defined in rfc9113 ch. 8.2.2
 * - lower-cases the header field names
 *
 * @param h2_headers will contain the HTTP/2 headers on success
 * @param req        the request to transform
 * @param data       the handle to lookup defaults like ' :scheme' from
 */
FETCHcode Fetch_http_req_to_h2(struct dynhds *h2_headers,
                              struct httpreq *req, struct Fetch_easy *data);

/**
 * All about a core HTTP response, excluding body and trailers
 */
struct http_resp
{
  int status;
  char *description;
  struct dynhds headers;
  struct dynhds trailers;
  struct http_resp *prev;
};

/**
 * Create an HTTP response struct.
 */
FETCHcode Fetch_http_resp_make(struct http_resp **presp,
                              int status,
                              const char *description);

void Fetch_http_resp_free(struct http_resp *resp);

#endif /* HEADER_FETCH_HTTP_H */
