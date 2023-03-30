#ifndef HEADER_CURL_HTTP_H
#define HEADER_CURL_HTTP_H
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

#if defined(USE_MSH3) && !defined(_WIN32)
#include <pthread.h>
#endif

#include "bufq.h"
#include "dynhds.h"
#include "ws.h"

typedef enum {
  HTTPREQ_GET,
  HTTPREQ_POST,
  HTTPREQ_POST_FORM, /* we make a difference internally */
  HTTPREQ_POST_MIME, /* we make a difference internally */
  HTTPREQ_PUT,
  HTTPREQ_HEAD
} Curl_HttpReq;

#ifndef CURL_DISABLE_HTTP

#if defined(ENABLE_QUIC) || defined(USE_NGHTTP2)
#include <stdint.h>
#endif

extern const struct Curl_handler Curl_handler_http;

#ifdef USE_SSL
extern const struct Curl_handler Curl_handler_https;
#endif

#ifdef USE_WEBSOCKETS
extern const struct Curl_handler Curl_handler_ws;

#ifdef USE_SSL
extern const struct Curl_handler Curl_handler_wss;
#endif
#endif /* websockets */

struct dynhds;

/* Header specific functions */
bool Curl_compareheader(const char *headerline,  /* line to check */
                        const char *header,   /* header keyword _with_ colon */
                        const size_t hlen,   /* len of the keyword in bytes */
                        const char *content, /* content string to find */
                        const size_t clen);   /* len of the content in bytes */

char *Curl_copy_header_value(const char *header);

char *Curl_checkProxyheaders(struct Curl_easy *data,
                             const struct connectdata *conn,
                             const char *thisheader,
                             const size_t thislen);
struct HTTP; /* see below */
CURLcode Curl_buffer_send(struct dynbuf *in,
                          struct Curl_easy *data,
                          struct HTTP *http,
                          curl_off_t *bytes_written,
                          curl_off_t included_body_bytes,
                          int socketindex);

CURLcode Curl_add_timecondition(struct Curl_easy *data,
#ifndef USE_HYPER
                                struct dynbuf *req
#else
                                void *headers
#endif
  );
CURLcode Curl_add_custom_headers(struct Curl_easy *data,
                                 bool is_connect,
#ifndef USE_HYPER
                                 struct dynbuf *req
#else
                                 void *headers
#endif
  );
CURLcode Curl_dynhds_add_custom(struct Curl_easy *data,
                                bool is_connect,
                                struct dynhds *hds);

CURLcode Curl_http_compile_trailers(struct curl_slist *trailers,
                                    struct dynbuf *buf,
                                    struct Curl_easy *handle);

void Curl_http_method(struct Curl_easy *data, struct connectdata *conn,
                      const char **method, Curl_HttpReq *);
CURLcode Curl_http_useragent(struct Curl_easy *data);
CURLcode Curl_http_host(struct Curl_easy *data, struct connectdata *conn);
CURLcode Curl_http_target(struct Curl_easy *data, struct connectdata *conn,
                          struct dynbuf *req);
CURLcode Curl_http_statusline(struct Curl_easy *data,
                              struct connectdata *conn);
CURLcode Curl_http_header(struct Curl_easy *data, struct connectdata *conn,
                          char *headp);
CURLcode Curl_transferencode(struct Curl_easy *data);
CURLcode Curl_http_body(struct Curl_easy *data, struct connectdata *conn,
                        Curl_HttpReq httpreq,
                        const char **teep);
CURLcode Curl_http_bodysend(struct Curl_easy *data, struct connectdata *conn,
                            struct dynbuf *r, Curl_HttpReq httpreq);
bool Curl_use_http_1_1plus(const struct Curl_easy *data,
                           const struct connectdata *conn);
#ifndef CURL_DISABLE_COOKIES
CURLcode Curl_http_cookies(struct Curl_easy *data,
                           struct connectdata *conn,
                           struct dynbuf *r);
#else
#define Curl_http_cookies(a,b,c) CURLE_OK
#endif
CURLcode Curl_http_resume(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_HttpReq httpreq);
CURLcode Curl_http_range(struct Curl_easy *data,
                         Curl_HttpReq httpreq);
CURLcode Curl_http_firstwrite(struct Curl_easy *data,
                              struct connectdata *conn,
                              bool *done);

/* protocol-specific functions set up to be called by the main engine */
CURLcode Curl_http(struct Curl_easy *data, bool *done);
CURLcode Curl_http_done(struct Curl_easy *data, CURLcode, bool premature);
CURLcode Curl_http_connect(struct Curl_easy *data, bool *done);

/* These functions are in http.c */
CURLcode Curl_http_input_auth(struct Curl_easy *data, bool proxy,
                              const char *auth);
CURLcode Curl_http_auth_act(struct Curl_easy *data);

/* If only the PICKNONE bit is set, there has been a round-trip and we
   selected to use no auth at all. Ie, we actively select no auth, as opposed
   to not having one selected. The other CURLAUTH_* defines are present in the
   public curl/curl.h header. */
#define CURLAUTH_PICKNONE (1<<30) /* don't use auth */

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
#define MAX_INITIAL_POST_SIZE (64*1024)
#endif

/* EXPECT_100_THRESHOLD is the request body size limit for when libcurl will
 * automatically add an "Expect: 100-continue" header in HTTP requests. When
 * the size is unknown, it will always add it.
 *
 */
#ifndef EXPECT_100_THRESHOLD
#define EXPECT_100_THRESHOLD (1024*1024)
#endif

#endif /* CURL_DISABLE_HTTP */

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/
struct HTTP {
  curl_mimepart *sendit;
  curl_off_t postsize; /* off_t to handle large file sizes */
  const char *postdata;

  const char *p_pragma;      /* Pragma: string */

  /* For FORM posting */
  curl_mimepart form;

  struct back {
    curl_read_callback fread_func; /* backup storage for fread pointer */
    void *fread_in;           /* backup storage for fread_in pointer */
    const char *postdata;
    curl_off_t postsize;
    struct Curl_easy *data;
  } backup;

  enum {
    HTTPSEND_NADA,    /* init */
    HTTPSEND_REQUEST, /* sending a request */
    HTTPSEND_BODY     /* sending body */
  } sending;

  void *impl_ctx;     /* context for actual HTTP implementation */

#ifdef USE_WEBSOCKETS
  struct websocket ws;
#endif

#ifndef CURL_DISABLE_HTTP
  struct dynbuf send_buffer; /* used if the request couldn't be sent in one
                                chunk, points to an allocated send_buffer
                                struct */
#endif
#ifdef USE_NGHTTP2
  /*********** for HTTP/2 we store stream-local data here *************/
  int32_t stream_id; /* stream we are interested in */
  struct bufq h2_sendbuf; /* request body data buffere for sending */
  size_t h2_send_hds_len; /* amount of bytes in first cf_send() that
                             are header bytes. Or 0 if not known. */
  struct bufq h2_recvbuf;
  size_t h2_recv_hds_len; /* how many bytes in recvbuf are headers */
  struct dynhds resp_trailers;
  bool close_handled; /* TRUE if stream closure is handled by libcurl */

  char **push_headers;       /* allocated array */
  size_t push_headers_used;  /* number of entries filled in */
  size_t push_headers_alloc; /* number of entries allocated */
  uint32_t error; /* HTTP/2 stream error code */
  bool bodystarted;
  int status_code; /* HTTP status code */
  char *mem;     /* points to a buffer in memory to store received data */
  size_t len;    /* size of the buffer 'mem' points to */
  size_t memlen; /* size of data copied to mem */
  /* fields used by both HTTP/2 and HTTP/3 */
  const uint8_t *upload_mem; /* points to a buffer to read from */
  size_t upload_len; /* size of the buffer 'upload_mem' points to */
  curl_off_t upload_left; /* number of bytes left to upload */
  bool closed; /* TRUE on stream close */
  bool reset;  /* TRUE on stream reset */
#endif
};

CURLcode Curl_http_size(struct Curl_easy *data);

CURLcode Curl_http_readwrite_headers(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     ssize_t *nread,
                                     bool *stop_reading);

/**
 * Curl_http_output_auth() setups the authentication headers for the
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
 * @returns CURLcode
 */
CURLcode
Curl_http_output_auth(struct Curl_easy *data,
                      struct connectdata *conn,
                      const char *request,
                      Curl_HttpReq httpreq,
                      const char *path,
                      bool proxytunnel); /* TRUE if this is the request setting
                                            up the proxy tunnel */

/* Decode HTTP status code string. */
CURLcode Curl_http_decode_status(int *pstatus, const char *s, size_t len);

/**
 * All about a core HTTP request, excluding body and trailers
 */
struct http_req {
  char method[12];
  char *scheme;
  char *authority;
  char *path;
  struct dynhds headers;
  struct dynhds trailers;
};

/**
 * Create a HTTP request struct.
 */
CURLcode Curl_http_req_make(struct http_req **preq,
                            const char *method,
                            const char *scheme,
                            const char *authority,
                            const char *path);

void Curl_http_req_free(struct http_req *req);

/**
 * All about a core HTTP response, excluding body and trailers
 */
struct http_resp {
  int status;
  char *description;
  struct dynhds headers;
  struct dynhds trailers;
  struct http_resp *prev;
};

/**
 * Create a HTTP response struct.
 */
CURLcode Curl_http_resp_make(struct http_resp **presp,
                             int status,
                             const char *description);

void Curl_http_resp_free(struct http_resp *resp);

#endif /* HEADER_CURL_HTTP_H */
