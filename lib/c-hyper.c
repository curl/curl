/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER)

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include <hyper.h>
#include "urldata.h"
#include "sendf.h"
#include "transfer.h"
#include "multiif.h"
#include "progress.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

size_t Curl_hyper_recv(void *userp, hyper_context *ctx,
                       uint8_t *buf, size_t buflen)
{
  struct Curl_easy *data = userp;
  struct connectdata *conn = data->conn;
  CURLcode result;
  ssize_t nread;
  DEBUGASSERT(conn);
  (void)ctx;

  result = Curl_read(data, conn->sockfd, (char *)buf, buflen, &nread);
  if(result == CURLE_AGAIN) {
    /* would block, register interest */
    if(data->hyp.read_waker)
      hyper_waker_free(data->hyp.read_waker);
    data->hyp.read_waker = hyper_context_waker(ctx);
    if(!data->hyp.read_waker) {
      failf(data, "Couldn't make the read hyper_context_waker");
      return HYPER_IO_ERROR;
    }
    return HYPER_IO_PENDING;
  }
  else if(result) {
    failf(data, "Curl_read failed");
    return HYPER_IO_ERROR;
  }
  return (size_t)nread;
}

size_t Curl_hyper_send(void *userp, hyper_context *ctx,
                       const uint8_t *buf, size_t buflen)
{
  struct Curl_easy *data = userp;
  struct connectdata *conn = data->conn;
  CURLcode result;
  ssize_t nwrote;

  result = Curl_write(data, conn->sockfd, (void *)buf, buflen, &nwrote);
  if(result == CURLE_AGAIN) {
    /* would block, register interest */
    if(data->hyp.write_waker)
      hyper_waker_free(data->hyp.write_waker);
    data->hyp.write_waker = hyper_context_waker(ctx);
    if(!data->hyp.write_waker) {
      failf(data, "Couldn't make the write hyper_context_waker");
      return HYPER_IO_ERROR;
    }
    return HYPER_IO_PENDING;
  }
  else if(result) {
    failf(data, "Curl_write failed");
    return HYPER_IO_ERROR;
  }
  return (size_t)nwrote;
}

static int hyper_each_header(void *userdata,
                             const uint8_t *name,
                             size_t name_len,
                             const uint8_t *value,
                             size_t value_len)
{
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  size_t len;
  char *headp;
  CURLcode result;
  Curl_dyn_reset(&data->state.headerb);
  if(name_len) {
    if(Curl_dyn_addf(&data->state.headerb, "%.*s: %.*s\r\n",
                     (int) name_len, name, (int) value_len, value))
      return HYPER_ITER_BREAK;
  }
  else {
    if(Curl_dyn_add(&data->state.headerb, "\r\n"))
      return HYPER_ITER_BREAK;
  }
  len = Curl_dyn_len(&data->state.headerb);
  headp = Curl_dyn_ptr(&data->state.headerb);

  result = Curl_http_header(data, data->conn, headp);
  if(result) {
    data->state.hresult = result;
    return HYPER_ITER_BREAK;
  }

  Curl_debug(data, CURLINFO_HEADER_IN, headp, len);

  result = Curl_client_write(data, CLIENTWRITE_HEADER, headp, len);
  if(result) {
    data->state.hresult = CURLE_ABORTED_BY_CALLBACK;
    return HYPER_ITER_BREAK;
  }

  data->info.header_size += (long)len;
  data->req.headerbytecount += (long)len;
  return HYPER_ITER_CONTINUE;
}

static int hyper_body_chunk(void *userdata, const hyper_buf *chunk)
{
  char *buf = (char *)hyper_buf_bytes(chunk);
  size_t len = hyper_buf_len(chunk);
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  struct SingleRequest *k = &data->req;
  CURLcode result;

  if(0 == k->bodywrites++) {
    bool done = FALSE;
    result = Curl_http_firstwrite(data, data->conn, &done);
    if(result || done) {
      infof(data, "Return early from hyper_body_chunk\n");
      data->state.hresult = result;
      return HYPER_ITER_BREAK;
    }
  }
  if(k->ignorebody)
    return HYPER_ITER_CONTINUE;
  Curl_debug(data, CURLINFO_DATA_IN, buf, len);
  result = Curl_client_write(data, CLIENTWRITE_BODY, buf, len);

  if(result) {
    data->state.hresult = result;
    return HYPER_ITER_BREAK;
  }

  data->req.bytecount += len;
  Curl_pgrsSetDownloadCounter(data, data->req.bytecount);
  return HYPER_ITER_CONTINUE;
}

/*
 * Hyper does not consider the status line, the first line in a HTTP/1
 * response, to be a header. The libcurl API does. This function sends the
 * status line in the header callback. */
static CURLcode status_line(struct Curl_easy *data,
                            struct connectdata *conn,
                            uint16_t http_status,
                            int http_version,
                            const uint8_t *reason, size_t rlen)
{
  CURLcode result;
  size_t wrote;
  size_t len;
  const char *vstr;
  curl_write_callback writeheader =
    data->set.fwrite_header? data->set.fwrite_header: data->set.fwrite_func;
  vstr = http_version == HYPER_HTTP_VERSION_1_1 ? "1.1" :
    (http_version == HYPER_HTTP_VERSION_2 ? "2" : "1.0");
  conn->httpversion =
    http_version == HYPER_HTTP_VERSION_1_1 ? 11 :
    (http_version == HYPER_HTTP_VERSION_2 ? 20 : 10);
  data->req.httpcode = http_status;

  result = Curl_http_statusline(data, conn);
  if(result)
    return result;

  Curl_dyn_reset(&data->state.headerb);

  result = Curl_dyn_addf(&data->state.headerb, "HTTP/%s %03d %.*s\r\n",
                         vstr,
                         (int)http_status,
                         (int)rlen, reason);
  if(result)
    return result;
  len = Curl_dyn_len(&data->state.headerb);
  Curl_debug(data, CURLINFO_HEADER_IN, Curl_dyn_ptr(&data->state.headerb),
             len);
  Curl_set_in_callback(data, true);
  wrote = writeheader(Curl_dyn_ptr(&data->state.headerb), 1, len,
                      data->set.writeheader);
  Curl_set_in_callback(data, false);
  if(wrote != len)
    return CURLE_WRITE_ERROR;

  data->info.header_size += (long)len;
  data->req.headerbytecount += (long)len;
  data->req.httpcode = http_status;
  return CURLE_OK;
}

/*
 * Hyper does not pass on the last empty response header. The libcurl API
 * does. This function sends an empty header in the header callback.
 */
static CURLcode empty_header(struct Curl_easy *data)
{
  return hyper_each_header(data, NULL, 0, NULL, 0) ?
    CURLE_WRITE_ERROR : CURLE_OK;
}

CURLcode Curl_hyper_stream(struct Curl_easy *data,
                           struct connectdata *conn,
                           int *didwhat,
                           bool *done,
                           int select_res)
{
  hyper_response *resp = NULL;
  uint16_t http_status;
  int http_version;
  hyper_headers *headers = NULL;
  hyper_body *resp_body = NULL;
  struct hyptransfer *h = &data->hyp;
  hyper_task *task;
  hyper_task *foreach;
  hyper_error *hypererr = NULL;
  const uint8_t *reasonp;
  size_t reason_len;
  CURLcode result = CURLE_OK;
  (void)conn;

  if(select_res & CURL_CSELECT_IN) {
    if(h->read_waker)
      hyper_waker_wake(h->read_waker);
    h->read_waker = NULL;
  }
  if(select_res & CURL_CSELECT_OUT) {
    if(h->write_waker)
      hyper_waker_wake(h->write_waker);
    h->write_waker = NULL;
  }

  *done = FALSE;
  do {
    hyper_task_return_type t;
    task = hyper_executor_poll(h->exec);
    if(!task) {
      *didwhat = KEEP_RECV;
      break;
    }
    t = hyper_task_type(task);
    switch(t) {
    case HYPER_TASK_ERROR:
      hypererr = hyper_task_value(task);
      break;
    case HYPER_TASK_RESPONSE:
      resp = hyper_task_value(task);
      break;
    default:
      break;
    }
    hyper_task_free(task);

    if(t == HYPER_TASK_ERROR) {
      hyper_code errnum = hyper_error_code(hypererr);
      if(errnum == HYPERE_ABORTED_BY_CALLBACK) {
        /* override Hyper's view, might not even be an error */
        result = data->state.hresult;
        infof(data, "hyperstream is done (by early callback)\n");
      }
      else {
        uint8_t errbuf[256];
        size_t errlen = hyper_error_print(hypererr, errbuf, sizeof(errbuf));
        hyper_code code = hyper_error_code(hypererr);
        failf(data, "Hyper: [%d] %.*s", (int)code, (int)errlen, errbuf);
        if((code == HYPERE_UNEXPECTED_EOF) && !data->req.bytecount)
          result = CURLE_GOT_NOTHING;
        else
          result = CURLE_RECV_ERROR;
      }
      *done = TRUE;
      hyper_error_free(hypererr);
      break;
    }
    else if(h->endtask == task) {
      /* end of transfer */
      *done = TRUE;
      infof(data, "hyperstream is done!\n");
      break;
    }
    else if(t != HYPER_TASK_RESPONSE) {
      *didwhat = KEEP_RECV;
      break;
    }
    /* HYPER_TASK_RESPONSE */

    *didwhat = KEEP_RECV;
    if(!resp) {
      failf(data, "hyperstream: couldn't get response");
      return CURLE_RECV_ERROR;
    }

    http_status = hyper_response_status(resp);
    http_version = hyper_response_version(resp);
    reasonp = hyper_response_reason_phrase(resp);
    reason_len = hyper_response_reason_phrase_len(resp);

    result = status_line(data, conn,
                         http_status, http_version, reasonp, reason_len);
    if(result)
      break;

    headers = hyper_response_headers(resp);
    if(!headers) {
      failf(data, "hyperstream: couldn't get response headers");
      result = CURLE_RECV_ERROR;
      break;
    }

    /* the headers are already received */
    hyper_headers_foreach(headers, hyper_each_header, data);
    if(data->state.hresult) {
      result = data->state.hresult;
      break;
    }

    if(empty_header(data)) {
      failf(data, "hyperstream: couldn't pass blank header");
      result = CURLE_OUT_OF_MEMORY;
      break;
    }

    /* Curl_http_auth_act() checks what authentication methods that are
     * available and decides which one (if any) to use. It will set 'newurl'
     * if an auth method was picked. */
    result = Curl_http_auth_act(data);
    if(result)
      break;

    resp_body = hyper_response_body(resp);
    if(!resp_body) {
      failf(data, "hyperstream: couldn't get response body");
      result = CURLE_RECV_ERROR;
      break;
    }
    foreach = hyper_body_foreach(resp_body, hyper_body_chunk, data);
    if(!foreach) {
      failf(data, "hyperstream: body foreach failed");
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    DEBUGASSERT(hyper_task_type(foreach) == HYPER_TASK_EMPTY);
    if(HYPERE_OK != hyper_executor_push(h->exec, foreach)) {
      failf(data, "Couldn't hyper_executor_push the body-foreach");
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    h->endtask = foreach;

    hyper_response_free(resp);
    resp = NULL;
  } while(1);
  if(resp)
    hyper_response_free(resp);
  return result;
}

static CURLcode debug_request(struct Curl_easy *data,
                              const char *method,
                              const char *path,
                              bool h2)
{
  char *req = aprintf("%s %s HTTP/%s\r\n", method, path,
                      h2?"2":"1.1");
  if(!req)
    return CURLE_OUT_OF_MEMORY;
  Curl_debug(data, CURLINFO_HEADER_OUT, req, strlen(req));
  free(req);
  return CURLE_OK;
}

/*
 * Given a full header line "name: value" (optional CRLF in the input, should
 * be in the output), add to Hyper and send to the debug callback.
 *
 * Supports multiple headers.
 */

CURLcode Curl_hyper_header(struct Curl_easy *data, hyper_headers *headers,
                           const char *line)
{
  const char *p;
  const char *n;
  size_t nlen;
  const char *v;
  size_t vlen;
  bool newline = TRUE;
  int numh = 0;

  if(!line)
    return CURLE_OK;
  n = line;
  do {
    size_t linelen = 0;

    p = strchr(n, ':');
    if(!p)
      /* this is fine if we already added at least one header */
      return numh ? CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
    nlen = p - n;
    p++; /* move past the colon */
    while(*p == ' ')
      p++;
    v = p;
    p = strchr(v, '\r');
    if(!p) {
      p = strchr(v, '\n');
      if(p)
        linelen = 1; /* LF only */
      else {
        p = strchr(v, '\0');
        newline = FALSE; /* no newline */
      }
    }
    else
      linelen = 2; /* CRLF ending */
    linelen += (p - n);
    if(!n)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    vlen = p - v;

    if(HYPERE_OK != hyper_headers_add(headers, (uint8_t *)n, nlen,
                                      (uint8_t *)v, vlen)) {
      failf(data, "hyper_headers_add host");
      return CURLE_OUT_OF_MEMORY;
    }
    if(data->set.verbose) {
      char *ptr = NULL;
      if(!newline) {
        ptr = aprintf("%.*s\r\n", (int)linelen, line);
        if(!ptr)
          return CURLE_OUT_OF_MEMORY;
        Curl_debug(data, CURLINFO_HEADER_OUT, ptr, linelen + 2);
        free(ptr);
      }
      else
        Curl_debug(data, CURLINFO_HEADER_OUT, (char *)line, linelen);
    }
    numh++;
    n += linelen;
  } while(newline);
  return CURLE_OK;
}

static CURLcode request_target(struct Curl_easy *data,
                               struct connectdata *conn,
                               const char *method,
                               bool h2,
                               hyper_request *req)
{
  CURLcode result;
  struct dynbuf r;

  Curl_dyn_init(&r, DYN_HTTP_REQUEST);

  result = Curl_http_target(data, conn, &r);
  if(result)
    return result;

  if(hyper_request_set_uri(req, (uint8_t *)Curl_dyn_uptr(&r),
                           Curl_dyn_len(&r))) {
    failf(data, "error setting path");
    result = CURLE_OUT_OF_MEMORY;
  }
  else
    result = debug_request(data, method, Curl_dyn_ptr(&r), h2);

  Curl_dyn_free(&r);

  return result;
}

static int uploadpostfields(void *userdata, hyper_context *ctx,
                            hyper_buf **chunk)
{
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  (void)ctx;
  if(data->req.upload_done)
    *chunk = NULL; /* nothing more to deliver */
  else {
    /* send everything off in a single go */
    *chunk = hyper_buf_copy(data->set.postfields,
                            (size_t)data->req.p.http->postsize);
    data->req.upload_done = TRUE;
  }
  return HYPER_POLL_READY;
}

static int uploadstreamed(void *userdata, hyper_context *ctx,
                          hyper_buf **chunk)
{
  size_t fillcount;
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  CURLcode result =
    Curl_fillreadbuffer(data, data->set.upload_buffer_size, &fillcount);
  (void)ctx;
  if(result)
    return HYPER_POLL_ERROR;
  if(!fillcount)
    /* done! */
    *chunk = NULL;
  else
    *chunk = hyper_buf_copy((uint8_t *)data->state.ulbuf, fillcount);
  return HYPER_POLL_READY;
}

/*
 * bodysend() sets up headers in the outgoing request for a HTTP transfer that
 * sends a body
 */

static CURLcode bodysend(struct Curl_easy *data,
                         struct connectdata *conn,
                         hyper_headers *headers,
                         hyper_request *hyperreq,
                         Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  struct dynbuf req;
  if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD))
    Curl_pgrsSetUploadSize(data, 0); /* no request body */
  else {
    hyper_body *body;
    Curl_dyn_init(&req, DYN_HTTP_REQUEST);
    result = Curl_http_bodysend(data, conn, &req, httpreq);

    if(!result)
      result = Curl_hyper_header(data, headers, Curl_dyn_ptr(&req));

    Curl_dyn_free(&req);

    body = hyper_body_new();
    hyper_body_set_userdata(body, data);
    if(data->set.postfields)
      hyper_body_set_data_func(body, uploadpostfields);
    else {
      result = Curl_get_upload_buffer(data);
      if(result)
        return result;
      /* init the "upload from here" pointer */
      data->req.upload_fromhere = data->state.ulbuf;
      hyper_body_set_data_func(body, uploadstreamed);
    }
    if(HYPERE_OK != hyper_request_set_body(hyperreq, body)) {
      /* fail */
      hyper_body_free(body);
      result = CURLE_OUT_OF_MEMORY;
    }
  }
  return result;
}

static CURLcode cookies(struct Curl_easy *data,
                        struct connectdata *conn,
                        hyper_headers *headers)
{
  struct dynbuf req;
  CURLcode result;
  Curl_dyn_init(&req, DYN_HTTP_REQUEST);

  result = Curl_http_cookies(data, conn, &req);
  if(!result)
    result = Curl_hyper_header(data, headers, Curl_dyn_ptr(&req));
  Curl_dyn_free(&req);
  return result;
}

/*
 * Curl_http() gets called from the generic multi_do() function when a HTTP
 * request is to be performed. This creates and sends a properly constructed
 * HTTP request.
 */
CURLcode Curl_http(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  struct hyptransfer *h = &data->hyp;
  hyper_io *io = NULL;
  hyper_clientconn_options *options = NULL;
  hyper_task *task = NULL; /* for the handshake */
  hyper_task *sendtask = NULL; /* for the send */
  hyper_clientconn *client = NULL;
  hyper_request *req = NULL;
  hyper_headers *headers = NULL;
  hyper_task *handshake = NULL;
  hyper_error *hypererr = NULL;
  CURLcode result;
  const char *p_accept; /* Accept: string */
  const char *method;
  Curl_HttpReq httpreq;
  bool h2 = FALSE;
  const char *te = NULL; /* transfer-encoding */

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that is not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;

  infof(data, "Time for the Hyper dance\n");
  memset(h, 0, sizeof(struct hyptransfer));

  result = Curl_http_host(data, conn);
  if(result)
    return result;

  Curl_http_method(data, conn, &method, &httpreq);

  /* setup the authentication headers */
  {
    char *pq = NULL;
    if(data->state.up.query) {
      pq = aprintf("%s?%s", data->state.up.path, data->state.up.query);
      if(!pq)
        return CURLE_OUT_OF_MEMORY;
    }
    result = Curl_http_output_auth(data, conn, method, httpreq,
                                   (pq ? pq : data->state.up.path), FALSE);
    free(pq);
    if(result)
      return result;
  }

  result = Curl_http_resume(data, conn, httpreq);
  if(result)
    return result;

  result = Curl_http_range(data, httpreq);
  if(result)
    return result;

  result = Curl_http_useragent(data);
  if(result)
    return result;

  io = hyper_io_new();
  if(!io) {
    failf(data, "Couldn't create hyper IO");
    goto error;
  }
  /* tell Hyper how to read/write network data */
  hyper_io_set_userdata(io, data);
  hyper_io_set_read(io, Curl_hyper_recv);
  hyper_io_set_write(io, Curl_hyper_send);

  /* create an executor to poll futures */
  if(!h->exec) {
    h->exec = hyper_executor_new();
    if(!h->exec) {
      failf(data, "Couldn't create hyper executor");
      goto error;
    }
  }

  options = hyper_clientconn_options_new();
  if(!options) {
    failf(data, "Couldn't create hyper client options");
    goto error;
  }
  if(conn->negnpn == CURL_HTTP_VERSION_2) {
    hyper_clientconn_options_http2(options, 1);
    h2 = TRUE;
  }

  hyper_clientconn_options_exec(options, h->exec);

  /* "Both the `io` and the `options` are consumed in this function call" */
  handshake = hyper_clientconn_handshake(io, options);
  if(!handshake) {
    failf(data, "Couldn't create hyper client handshake");
    goto error;
  }
  io = NULL;
  options = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, handshake)) {
    failf(data, "Couldn't hyper_executor_push the handshake");
    goto error;
  }
  handshake = NULL; /* ownership passed on */

  task = hyper_executor_poll(h->exec);
  if(!task) {
    failf(data, "Couldn't hyper_executor_poll the handshake");
    goto error;
  }

  client = hyper_task_value(task);
  hyper_task_free(task);

  req = hyper_request_new();
  if(!req) {
    failf(data, "Couldn't hyper_request_new");
    goto error;
  }

  if(data->state.httpwant == CURL_HTTP_VERSION_1_0) {
    if(HYPERE_OK != hyper_request_set_version(req,
                                              HYPER_HTTP_VERSION_1_0)) {
      failf(data, "error setting HTTP version");
      goto error;
    }
  }

  if(hyper_request_set_method(req, (uint8_t *)method, strlen(method))) {
    failf(data, "error setting method");
    goto error;
  }

  result = request_target(data, conn, method, h2, req);
  if(result)
    goto error;

  headers = hyper_request_headers(req);
  if(!headers) {
    failf(data, "hyper_request_headers");
    goto error;
  }

  result = Curl_http_body(data, conn, httpreq, &te);
  if(result)
    return result;

  if(data->state.aptr.host &&
     Curl_hyper_header(data, headers, data->state.aptr.host))
    goto error;

  if(data->state.aptr.proxyuserpwd &&
     Curl_hyper_header(data, headers, data->state.aptr.proxyuserpwd))
    goto error;

  if(data->state.aptr.userpwd &&
     Curl_hyper_header(data, headers, data->state.aptr.userpwd))
    goto error;

  if((data->state.use_range && data->state.aptr.rangeline) &&
     Curl_hyper_header(data, headers, data->state.aptr.rangeline))
    goto error;

  if(data->set.str[STRING_USERAGENT] &&
     *data->set.str[STRING_USERAGENT] &&
     data->state.aptr.uagent &&
     Curl_hyper_header(data, headers, data->state.aptr.uagent))
    goto error;

  p_accept = Curl_checkheaders(data, "Accept")?NULL:"Accept: */*\r\n";
  if(p_accept && Curl_hyper_header(data, headers, p_accept))
    goto error;

  if(te && Curl_hyper_header(data, headers, te))
    goto error;

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy &&
     !Curl_checkheaders(data, "Proxy-Connection") &&
     !Curl_checkProxyheaders(data, conn, "Proxy-Connection")) {
    if(Curl_hyper_header(data, headers, "Proxy-Connection: Keep-Alive"))
      goto error;
  }
#endif

  Curl_safefree(data->state.aptr.ref);
  if(data->change.referer && !Curl_checkheaders(data, "Referer")) {
    data->state.aptr.ref = aprintf("Referer: %s\r\n", data->change.referer);
    if(!data->state.aptr.ref)
      return CURLE_OUT_OF_MEMORY;
    if(Curl_hyper_header(data, headers, data->state.aptr.ref))
      goto error;
  }

  result = cookies(data, conn, headers);
  if(result)
    return result;

  result = Curl_add_timecondition(data, headers);
  if(result)
    return result;

  result = Curl_add_custom_headers(data, FALSE, headers);
  if(result)
    return result;

  result = bodysend(data, conn, headers, req, httpreq);
  if(result)
    return result;

  Curl_debug(data, CURLINFO_HEADER_OUT, (char *)"\r\n", 2);

  data->req.upload_chunky = FALSE;
  sendtask = hyper_clientconn_send(client, req);
  if(!sendtask) {
    failf(data, "hyper_clientconn_send");
    goto error;
  }

  if(HYPERE_OK != hyper_executor_push(h->exec, sendtask)) {
    failf(data, "Couldn't hyper_executor_push the send");
    goto error;
  }

  hyper_clientconn_free(client);

  do {
    task = hyper_executor_poll(h->exec);
    if(task) {
      bool error = hyper_task_type(task) == HYPER_TASK_ERROR;
      if(error)
        hypererr = hyper_task_value(task);
      hyper_task_free(task);
      if(error)
        goto error;
    }
  } while(task);

  if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) {
    /* HTTP GET/HEAD download */
    Curl_pgrsSetUploadSize(data, 0); /* nothing */
    Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
  }
  conn->datastream = Curl_hyper_stream;

  return CURLE_OK;
  error:

  if(io)
    hyper_io_free(io);

  if(options)
    hyper_clientconn_options_free(options);

  if(handshake)
    hyper_task_free(handshake);

  if(hypererr) {
    uint8_t errbuf[256];
    size_t errlen = hyper_error_print(hypererr, errbuf, sizeof(errbuf));
    hyper_code code = hyper_error_code(hypererr);
    failf(data, "Hyper: [%d] %.*s", (int)code, (int)errlen, errbuf);
    hyper_error_free(hypererr);
  }
  return CURLE_OUT_OF_MEMORY;
}

void Curl_hyper_done(struct Curl_easy *data)
{
  struct hyptransfer *h = &data->hyp;
  if(h->exec) {
    hyper_executor_free(h->exec);
    h->exec = NULL;
  }
  if(h->read_waker) {
    hyper_waker_free(h->read_waker);
    h->read_waker = NULL;
  }
  if(h->write_waker) {
    hyper_waker_free(h->write_waker);
    h->write_waker = NULL;
  }
}

#endif /* !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER) */
