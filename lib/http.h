#ifndef HEADER_CURL_HTTP_H
#define HEADER_CURL_HTTP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "curl_setup.h"

#ifndef CURL_DISABLE_HTTP

#ifdef USE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif

extern const struct Curl_handler Curl_handler_http;

#ifdef USE_SSL
extern const struct Curl_handler Curl_handler_https;
#endif

/* Header specific functions */
bool Curl_compareheader(const char *headerline,  /* line to check */
                        const char *header,   /* header keyword _with_ colon */
                        const char *content); /* content string to find */

char *Curl_checkheaders(const struct connectdata *conn,
                        const char *thisheader);
char *Curl_copy_header_value(const char *header);

char *Curl_checkProxyheaders(const struct connectdata *conn,
                             const char *thisheader);
/* ------------------------------------------------------------------------- */
/*
 * The add_buffer series of functions are used to build one large memory chunk
 * from repeated function invokes. Used so that the entire HTTP request can
 * be sent in one go.
 */
struct Curl_send_buffer {
  char *buffer;
  size_t size_max;
  size_t size_used;
};
typedef struct Curl_send_buffer Curl_send_buffer;

Curl_send_buffer *Curl_add_buffer_init(void);
CURLcode Curl_add_bufferf(Curl_send_buffer *in, const char *fmt, ...);
CURLcode Curl_add_buffer(Curl_send_buffer *in, const void *inptr, size_t size);
CURLcode Curl_add_buffer_send(Curl_send_buffer *in,
                              struct connectdata *conn,
                              long *bytes_written,
                              size_t included_body_bytes,
                              int socketindex);

CURLcode Curl_add_timecondition(struct SessionHandle *data,
                                Curl_send_buffer *buf);
CURLcode Curl_add_custom_headers(struct connectdata *conn,
                                 bool is_connect,
                                 Curl_send_buffer *req_buffer);

/* protocol-specific functions set up to be called by the main engine */
CURLcode Curl_http(struct connectdata *conn, bool *done);
CURLcode Curl_http_done(struct connectdata *, CURLcode, bool premature);
CURLcode Curl_http_connect(struct connectdata *conn, bool *done);
CURLcode Curl_http_setup_conn(struct connectdata *conn);

/* The following functions are defined in http_chunks.c */
void Curl_httpchunk_init(struct connectdata *conn);
CHUNKcode Curl_httpchunk_read(struct connectdata *conn, char *datap,
                              ssize_t length, ssize_t *wrote);

/* These functions are in http.c */
void Curl_http_auth_stage(struct SessionHandle *data, int stage);
CURLcode Curl_http_input_auth(struct connectdata *conn, bool proxy,
                              const char *auth);
CURLcode Curl_http_auth_act(struct connectdata *conn);
CURLcode Curl_http_perhapsrewind(struct connectdata *conn);

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
   will always be uncondtionally sent and thus it may not be larger than can
   always be afforded to send twice.

   It must not be greater than 64K to work on VMS.
*/
#ifndef MAX_INITIAL_POST_SIZE
#define MAX_INITIAL_POST_SIZE (64*1024)
#endif

#ifndef TINY_INITIAL_POST_SIZE
#define TINY_INITIAL_POST_SIZE 1024
#endif

#endif /* CURL_DISABLE_HTTP */

/****************************************************************************
 * HTTP unique setup
 ***************************************************************************/
struct HTTP {
  struct FormData *sendit;
  curl_off_t postsize; /* off_t to handle large file sizes */
  const char *postdata;

  const char *p_pragma;      /* Pragma: string */
  const char *p_accept;      /* Accept: string */
  curl_off_t readbytecount;
  curl_off_t writebytecount;

  /* For FORM posting */
  struct Form form;

  struct back {
    curl_read_callback fread_func; /* backup storage for fread pointer */
    void *fread_in;           /* backup storage for fread_in pointer */
    const char *postdata;
    curl_off_t postsize;
  } backup;

  enum {
    HTTPSEND_NADA,    /* init */
    HTTPSEND_REQUEST, /* sending a request */
    HTTPSEND_BODY,    /* sending body */
    HTTPSEND_LAST     /* never use this */
  } sending;

  void *send_buffer; /* used if the request couldn't be sent in one chunk,
                        points to an allocated send_buffer struct */
};

typedef int (*sending)(void); /* Curl_send */
typedef int (*recving)(void); /* Curl_recv */

struct http_conn {
#ifdef USE_NGHTTP2
#define H2_BINSETTINGS_LEN 80
  nghttp2_session *h2;
  uint8_t binsettings[H2_BINSETTINGS_LEN];
  size_t  binlen; /* length of the binsettings data */
  char *mem;     /* points to a buffer in memory to store */
  size_t len;    /* size of the buffer 'mem' points to */
  bool bodystarted;
  sending send_underlying; /* underlying send Curl_send callback */
  recving recv_underlying; /* underlying recv Curl_recv callback */
  bool closed; /* TRUE on HTTP2 stream close */
  Curl_send_buffer *header_recvbuf; /* store response headers.  We
                                       store non-final and final
                                       response headers into it. */
  size_t nread_header_recvbuf; /* number of bytes in header_recvbuf
                                  fed into upper layer */
  int32_t stream_id; /* stream we are interested in */
  const uint8_t *data; /* pointer to data chunk, received in
                          on_data_chunk */
  size_t datalen; /* the number of bytes left in data */
  char *inbuf; /* buffer to receive data from underlying socket */
  /* We need separate buffer for transmission and reception because we
     may call nghttp2_session_send() after the
     nghttp2_session_mem_recv() but mem buffer is still not full. In
     this case, we wrongly sends the content of mem buffer if we share
     them for both cases. */
  const uint8_t *upload_mem; /* points to a buffer to read from */
  size_t upload_len; /* size of the buffer 'upload_mem' points to */
  size_t upload_left; /* number of bytes left to upload */
  int status_code; /* HTTP status code */
#else
  int unused; /* prevent a compiler warning */
#endif
};

CURLcode Curl_http_readwrite_headers(struct SessionHandle *data,
                                     struct connectdata *conn,
                                     ssize_t *nread,
                                     bool *stop_reading);

/**
 * Curl_http_output_auth() setups the authentication headers for the
 * host/proxy and the correct authentication
 * method. conn->data->state.authdone is set to TRUE when authentication is
 * done.
 *
 * @param conn all information about the current connection
 * @param request pointer to the request keyword
 * @param path pointer to the requested path
 * @param proxytunnel boolean if this is the request setting up a "proxy
 * tunnel"
 *
 * @returns CURLcode
 */
CURLcode
Curl_http_output_auth(struct connectdata *conn,
                      const char *request,
                      const char *path,
                      bool proxytunnel); /* TRUE if this is the request setting
                                            up the proxy tunnel */

#endif /* HEADER_CURL_HTTP_H */

