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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

/* Curl's integration with Hyper. This replaces certain functions in http.c,
 * based on configuration #defines. This implementation supports HTTP/1.1 but
 * not HTTP/2.
 */
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
#include "cfilters.h"
#include "sendf.h"
#include "headers.h"
#include "transfer.h"
#include "multiif.h"
#include "progress.h"
#include "content_encoding.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static CURLcode cr_hyper_add(struct Curl_easy *data);

typedef enum {
    USERDATA_NOT_SET = 0, /* for tasks with no userdata set; must be zero */
    USERDATA_RESP_BODY
} userdata_t;

size_t Curl_hyper_recv(void *userp, hyper_context *ctx,
                       uint8_t *buf, size_t buflen)
{
  struct hyp_io_ctx *io_ctx = userp;
  struct Curl_easy *data = io_ctx->data;
  struct connectdata *conn = data->conn;
  CURLcode result;
  ssize_t nread;
  DEBUGASSERT(conn);
  (void)ctx;

  DEBUGF(infof(data, "Curl_hyper_recv(%zu)", buflen));
  result = Curl_conn_recv(data, io_ctx->sockindex,
                          (char *)buf, buflen, &nread);
  if(result == CURLE_AGAIN) {
    /* would block, register interest */
    DEBUGF(infof(data, "Curl_hyper_recv(%zu) -> EAGAIN", buflen));
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
  DEBUGF(infof(data, "Curl_hyper_recv(%zu) -> %zd", buflen, nread));
  return (size_t)nread;
}

size_t Curl_hyper_send(void *userp, hyper_context *ctx,
                       const uint8_t *buf, size_t buflen)
{
  struct hyp_io_ctx *io_ctx = userp;
  struct Curl_easy *data = io_ctx->data;
  CURLcode result;
  size_t nwrote;

  DEBUGF(infof(data, "Curl_hyper_send(%zu)", buflen));
  result = Curl_conn_send(data, io_ctx->sockindex,
                          (void *)buf, buflen, FALSE, &nwrote);
  if(result == CURLE_AGAIN) {
    DEBUGF(infof(data, "Curl_hyper_send(%zu) -> EAGAIN", buflen));
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
  DEBUGF(infof(data, "Curl_hyper_send(%zu) -> %zd", buflen, nwrote));
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
  int writetype;

  if(name_len + value_len + 2 > CURL_MAX_HTTP_HEADER) {
    failf(data, "Too long response header");
    data->state.hresult = CURLE_TOO_LARGE;
    return HYPER_ITER_BREAK;
  }

  Curl_dyn_reset(&data->state.headerb);
  if(name_len) {
    if(Curl_dyn_addf(&data->state.headerb, "%.*s: %.*s\r\n",
                     (int) name_len, name, (int) value_len, value))
      return HYPER_ITER_BREAK;
  }
  else {
    if(Curl_dyn_addn(&data->state.headerb, STRCONST("\r\n")))
      return HYPER_ITER_BREAK;
  }
  len = Curl_dyn_len(&data->state.headerb);
  headp = Curl_dyn_ptr(&data->state.headerb);

  result = Curl_http_header(data, headp, len);
  if(result) {
    data->state.hresult = result;
    return HYPER_ITER_BREAK;
  }

  Curl_debug(data, CURLINFO_HEADER_IN, headp, len);

  writetype = CLIENTWRITE_HEADER;
  if(data->state.hconnect)
    writetype |= CLIENTWRITE_CONNECT;
  if(data->req.httpcode/100 == 1)
    writetype |= CLIENTWRITE_1XX;
  result = Curl_client_write(data, writetype, headp, len);
  if(result) {
    data->state.hresult = CURLE_ABORTED_BY_CALLBACK;
    return HYPER_ITER_BREAK;
  }

  result = Curl_bump_headersize(data, len, FALSE);
  if(result) {
    data->state.hresult = result;
    return HYPER_ITER_BREAK;
  }
  return HYPER_ITER_CONTINUE;
}

static int hyper_body_chunk(void *userdata, const hyper_buf *chunk)
{
  char *buf = (char *)hyper_buf_bytes(chunk);
  size_t len = hyper_buf_len(chunk);
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;

  if(!k->bodywritten) {
#if defined(USE_NTLM)
    struct connectdata *conn = data->conn;
    if(conn->bits.close &&
       (((data->req.httpcode == 401) &&
         (conn->http_ntlm_state == NTLMSTATE_TYPE2)) ||
        ((data->req.httpcode == 407) &&
         (conn->proxy_ntlm_state == NTLMSTATE_TYPE2)))) {
      infof(data, "Connection closed while negotiating NTLM");
      data->state.authproblem = TRUE;
      Curl_safefree(data->req.newurl);
    }
#endif
    if(Curl_http_exp100_is_selected(data)) {
      if(data->req.httpcode < 400) {
        Curl_http_exp100_got100(data);
        if(data->hyp.send_body_waker) {
          hyper_waker_wake(data->hyp.send_body_waker);
          data->hyp.send_body_waker = NULL;
        }
      }
      else { /* >= 4xx */
        Curl_req_abort_sending(data);
      }
    }
    if(data->state.hconnect && (data->req.httpcode/100 != 2) &&
       data->state.authproxy.done) {
      data->req.done = TRUE;
      result = CURLE_OK;
    }
    else
      result = Curl_http_firstwrite(data);
    if(result || data->req.done) {
      infof(data, "Return early from hyper_body_chunk");
      data->state.hresult = result;
      return HYPER_ITER_BREAK;
    }
  }
  result = Curl_client_write(data, CLIENTWRITE_BODY, buf, len);

  if(result) {
    data->state.hresult = result;
    return HYPER_ITER_BREAK;
  }

  return HYPER_ITER_CONTINUE;
}

/*
 * Hyper does not consider the status line, the first line in an HTTP/1
 * response, to be a header. The libcurl API does. This function sends the
 * status line in the header callback. */
static CURLcode status_line(struct Curl_easy *data,
                            struct connectdata *conn,
                            uint16_t http_status,
                            int http_version,
                            const uint8_t *reason, size_t rlen)
{
  CURLcode result;
  size_t len;
  const char *vstr;
  int writetype;
  vstr = http_version == HYPER_HTTP_VERSION_1_1 ? "1.1" :
    (http_version == HYPER_HTTP_VERSION_2 ? "2" : "1.0");

  /* We need to set 'httpcodeq' for functions that check the response code in
     a single place. */
  data->req.httpcode = http_status;
  data->req.httpversion = http_version == HYPER_HTTP_VERSION_1_1 ? 11 :
                          (http_version == HYPER_HTTP_VERSION_2 ? 20 : 10);
  if(data->state.hconnect)
    /* CONNECT */
    data->info.httpproxycode = http_status;
  else {
    conn->httpversion = (unsigned char)data->req.httpversion;
    if(http_version == HYPER_HTTP_VERSION_1_0)
      data->state.httpwant = CURL_HTTP_VERSION_1_0;

    result = Curl_http_statusline(data, conn);
    if(result)
      return result;
  }

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

  writetype = CLIENTWRITE_HEADER|CLIENTWRITE_STATUS;
  if(data->state.hconnect)
    writetype |= CLIENTWRITE_CONNECT;
  result = Curl_client_write(data, writetype,
                             Curl_dyn_ptr(&data->state.headerb), len);
  if(result)
    return result;

  result = Curl_bump_headersize(data, len, FALSE);
  return result;
}

/*
 * Hyper does not pass on the last empty response header. The libcurl API
 * does. This function sends an empty header in the header callback.
 */
static CURLcode empty_header(struct Curl_easy *data)
{
  CURLcode result = Curl_http_size(data);
  if(!result) {
    result = hyper_each_header(data, NULL, 0, NULL, 0) ?
      CURLE_WRITE_ERROR : CURLE_OK;
    if(result)
      failf(data, "hyperstream: could not pass blank header");
    /* Hyper does chunked decoding itself. If it was added during
     * response header processing, remove it again. */
    Curl_cwriter_remove_by_name(data, "chunked");
  }
  return result;
}

CURLcode Curl_hyper_stream(struct Curl_easy *data,
                           struct connectdata *conn,
                           int *didwhat,
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
  const uint8_t *reasonp;
  size_t reason_len;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  (void)conn;

  if(data->hyp.send_body_waker) {
    /* If there is still something to upload, wake it to give it
     * another try. */
    hyper_waker_wake(data->hyp.send_body_waker);
    data->hyp.send_body_waker = NULL;
  }

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

  while(1) {
    hyper_task_return_type t;
    task = hyper_executor_poll(h->exec);
    if(!task) {
      *didwhat = KEEP_RECV;
      break;
    }
    t = hyper_task_type(task);
    if(t == HYPER_TASK_ERROR) {
      hyper_error *hypererr = hyper_task_value(task);
      hyper_task_free(task);
      if(data->state.hresult) {
        /* override Hyper's view, might not even be an error */
        result = data->state.hresult;
        infof(data, "hyperstream is done (by early callback)");
      }
      else {
        uint8_t errbuf[256];
        size_t errlen = hyper_error_print(hypererr, errbuf, sizeof(errbuf));
        hyper_code code = hyper_error_code(hypererr);
        failf(data, "Hyper: [%d] %.*s", (int)code, (int)errlen, errbuf);
        switch(code) {
        case HYPERE_ABORTED_BY_CALLBACK:
          result = CURLE_OK;
          goto out;
        case HYPERE_UNEXPECTED_EOF:
          if(!data->req.bytecount)
            result = CURLE_GOT_NOTHING;
          else
            result = CURLE_RECV_ERROR;
          goto out;
        case HYPERE_INVALID_PEER_MESSAGE:
          /* bump headerbytecount to avoid the count remaining at zero and
             appearing to not having read anything from the peer at all */
          data->req.headerbytecount++;
          result = CURLE_UNSUPPORTED_PROTOCOL; /* maybe */
          goto out;
        default:
          result = CURLE_RECV_ERROR;
          goto out;
        }
      }
      data->req.done = TRUE;
      hyper_error_free(hypererr);
      break;
    }
    else if(t == HYPER_TASK_EMPTY) {
      void *userdata = hyper_task_userdata(task);
      hyper_task_free(task);
      if(userdata == (void *)USERDATA_RESP_BODY) {
        /* end of transfer */
        data->req.done = TRUE;
        infof(data, "hyperstream is done");
        if(!k->bodywritten) {
          /* hyper does not always call the body write callback */
          result = Curl_http_firstwrite(data);
        }
        break;
      }
      else {
        /* A background task for hyper; ignore */
        DEBUGF(infof(data, "hyper: some background task done"));
        continue;
      }
    }
    else if(t == HYPER_TASK_RESPONSE) {
      resp = hyper_task_value(task);
      hyper_task_free(task);

      *didwhat = KEEP_RECV;
      if(!resp) {
        failf(data, "hyperstream: could not get response");
        result = CURLE_RECV_ERROR;
        goto out;
      }

      http_status = hyper_response_status(resp);
      http_version = hyper_response_version(resp);
      reasonp = hyper_response_reason_phrase(resp);
      reason_len = hyper_response_reason_phrase_len(resp);

      if(http_status == 417 && Curl_http_exp100_is_selected(data)) {
        infof(data, "Got 417 while waiting for a 100");
        data->state.disableexpect = TRUE;
        data->req.newurl = strdup(data->state.url);
        Curl_req_abort_sending(data);
      }

      result = status_line(data, conn,
                           http_status, http_version, reasonp, reason_len);
      if(result)
        goto out;

      headers = hyper_response_headers(resp);
      if(!headers) {
        failf(data, "hyperstream: could not get response headers");
        result = CURLE_RECV_ERROR;
        goto out;
      }

      /* the headers are already received */
      hyper_headers_foreach(headers, hyper_each_header, data);
      if(data->state.hresult) {
        result = data->state.hresult;
        goto out;
      }

      result = empty_header(data);
      if(result)
        goto out;

      k->deductheadercount =
        (100 <= http_status && 199 >= http_status) ? k->headerbytecount : 0;
#ifndef CURL_DISABLE_WEBSOCKETS
      if(k->upgr101 == UPGR101_WS) {
        if(http_status == 101) {
          /* verify the response */
          result = Curl_ws_accept(data, NULL, 0);
          if(result)
            goto out;
        }
        else {
          failf(data, "Expected 101, got %u", k->httpcode);
          result = CURLE_HTTP_RETURNED_ERROR;
          goto out;
        }
      }
#endif

      /* Curl_http_auth_act() checks what authentication methods that are
       * available and decides which one (if any) to use. It will set 'newurl'
       * if an auth method was picked. */
      result = Curl_http_auth_act(data);
      if(result)
        goto out;

      resp_body = hyper_response_body(resp);
      if(!resp_body) {
        failf(data, "hyperstream: could not get response body");
        result = CURLE_RECV_ERROR;
        goto out;
      }
      foreach = hyper_body_foreach(resp_body, hyper_body_chunk, data);
      if(!foreach) {
        failf(data, "hyperstream: body foreach failed");
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      hyper_task_set_userdata(foreach, (void *)USERDATA_RESP_BODY);
      if(HYPERE_OK != hyper_executor_push(h->exec, foreach)) {
        failf(data, "Couldn't hyper_executor_push the body-foreach");
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }

      hyper_response_free(resp);
      resp = NULL;
    }
    else {
      DEBUGF(infof(data, "hyper: unhandled tasktype %x", t));
    }
  } /* while(1) */

  if(!result && Curl_xfer_needs_flush(data)) {
    DEBUGF(infof(data, "Curl_hyper_stream(), connection needs flush"));
    result = Curl_xfer_flush(data);
  }

out:
  DEBUGF(infof(data, "Curl_hyper_stream() -> %d", result));
  if(resp)
    hyper_response_free(resp);
  return result;
}

static CURLcode debug_request(struct Curl_easy *data,
                              const char *method,
                              const char *path)
{
  char *req = aprintf("%s %s HTTP/1.1\r\n", method, path);
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
    vlen = p - v;

    if(HYPERE_OK != hyper_headers_add(headers, (uint8_t *)n, nlen,
                                      (uint8_t *)v, vlen)) {
      failf(data, "hyper refused to add header '%s'", line);
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
        Curl_debug(data, CURLINFO_HEADER_OUT, (char *)n, linelen);
    }
    numh++;
    n += linelen;
  } while(newline);
  return CURLE_OK;
}

static CURLcode request_target(struct Curl_easy *data,
                               struct connectdata *conn,
                               const char *method,
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
    failf(data, "error setting uri to hyper");
    result = CURLE_OUT_OF_MEMORY;
  }
  else
    result = debug_request(data, method, Curl_dyn_ptr(&r));

  Curl_dyn_free(&r);

  return result;
}

static int uploadstreamed(void *userdata, hyper_context *ctx,
                          hyper_buf **chunk)
{
  size_t fillcount;
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  CURLcode result;
  char *xfer_ulbuf;
  size_t xfer_ulblen;
  bool eos;
  int rc = HYPER_POLL_ERROR;
  (void)ctx;

  result = Curl_multi_xfer_ulbuf_borrow(data, &xfer_ulbuf, &xfer_ulblen);
  if(result)
    goto out;

  result = Curl_client_read(data, xfer_ulbuf, xfer_ulblen, &fillcount, &eos);
  if(result)
    goto out;

  if(fillcount) {
    hyper_buf *copy = hyper_buf_copy((uint8_t *)xfer_ulbuf, fillcount);
    if(copy)
      *chunk = copy;
    else {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    /* increasing the writebytecount here is a little premature but we
       do not know exactly when the body is sent */
    data->req.writebytecount += fillcount;
    if(eos)
      data->req.eos_read = TRUE;
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    rc = HYPER_POLL_READY;
  }
  else if(eos) {
    data->req.eos_read = TRUE;
    *chunk = NULL;
    rc = HYPER_POLL_READY;
  }
  else {
    /* paused, save a waker */
    if(data->hyp.send_body_waker)
      hyper_waker_free(data->hyp.send_body_waker);
    data->hyp.send_body_waker = hyper_context_waker(ctx);
    rc = HYPER_POLL_PENDING;
  }

  if(!data->req.upload_done && data->req.eos_read) {
    DEBUGF(infof(data, "hyper: uploadstreamed(), upload is done"));
    result = Curl_req_set_upload_done(data);
  }

out:
  Curl_multi_xfer_ulbuf_release(data, xfer_ulbuf);
  data->state.hresult = result;
  DEBUGF(infof(data, "hyper: uploadstreamed() -> %d", result));
  return rc;
}

/*
 * finalize_request() sets up last headers and optional body settings
 */
static CURLcode finalize_request(struct Curl_easy *data,
                                 hyper_headers *headers,
                                 hyper_request *hyperreq,
                                 Curl_HttpReq httpreq)
{
  CURLcode result = CURLE_OK;
  struct dynbuf req;
  if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) {
    Curl_pgrsSetUploadSize(data, 0); /* no request body */
  }
  else {
    hyper_body *body;
    Curl_dyn_init(&req, DYN_HTTP_REQUEST);
    result = Curl_http_req_complete(data, &req, httpreq);
    if(result)
      return result;

    /* if the "complete" above did produce more than the closing line,
       parse the added headers */
    if(Curl_dyn_len(&req) != 2 || strcmp(Curl_dyn_ptr(&req), "\r\n")) {
      result = Curl_hyper_header(data, headers, Curl_dyn_ptr(&req));
      if(result)
        return result;
    }

    Curl_dyn_free(&req);

    body = hyper_body_new();
    hyper_body_set_userdata(body, data);
    hyper_body_set_data_func(body, uploadstreamed);

    if(HYPERE_OK != hyper_request_set_body(hyperreq, body)) {
      /* fail */
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  return cr_hyper_add(data);
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

/* called on 1xx responses */
static void http1xx_cb(void *arg, struct hyper_response *resp)
{
  struct Curl_easy *data = (struct Curl_easy *)arg;
  hyper_headers *headers = NULL;
  CURLcode result = CURLE_OK;
  uint16_t http_status;
  int http_version;
  const uint8_t *reasonp;
  size_t reason_len;

  infof(data, "Got HTTP 1xx informational");

  http_status = hyper_response_status(resp);
  http_version = hyper_response_version(resp);
  reasonp = hyper_response_reason_phrase(resp);
  reason_len = hyper_response_reason_phrase_len(resp);

  result = status_line(data, data->conn,
                       http_status, http_version, reasonp, reason_len);
  if(!result) {
    headers = hyper_response_headers(resp);
    if(!headers) {
      failf(data, "hyperstream: could not get 1xx response headers");
      result = CURLE_RECV_ERROR;
    }
  }
  data->state.hresult = result;

  if(!result) {
    /* the headers are already received */
    hyper_headers_foreach(headers, hyper_each_header, data);
    /* this callback also sets data->state.hresult on error */

    if(empty_header(data))
      result = CURLE_OUT_OF_MEMORY;
  }

  if(data->state.hresult)
    infof(data, "ERROR in 1xx, bail out");
}

/*
 * Curl_http() gets called from the generic multi_do() function when an HTTP
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
  CURLcode result;
  const char *p_accept; /* Accept: string */
  const char *method;
  Curl_HttpReq httpreq;
  const char *te = NULL; /* transfer-encoding */
  hyper_code rc;

  /* Always consider the DO phase done after this function call, even if there
     may be parts of the request that is not yet sent, since we can deal with
     the rest of the request in the PERFORM phase. */
  *done = TRUE;
  result = Curl_client_start(data);
  if(result)
    goto out;

  /* Add collecting of headers written to client. For a new connection,
   * we might have done that already, but reuse
   * or multiplex needs it here as well. */
  result = Curl_headers_init(data);
  if(result)
    goto out;

  infof(data, "Time for the Hyper dance");
  memset(h, 0, sizeof(struct hyptransfer));

  result = Curl_http_host(data, conn);
  if(result)
    goto out;

  Curl_http_method(data, conn, &method, &httpreq);

  DEBUGASSERT(data->req.bytecount ==  0);

  /* setup the authentication headers */
  {
    char *pq = NULL;
    if(data->state.up.query) {
      pq = aprintf("%s?%s", data->state.up.path, data->state.up.query);
      if(!pq) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
    }
    result = Curl_http_output_auth(data, conn, method, httpreq,
                                   (pq ? pq : data->state.up.path), FALSE);
    free(pq);
    if(result)
      goto out;
  }

  result = Curl_http_req_set_reader(data, httpreq, &te);
  if(result)
    goto out;

  result = Curl_http_range(data, httpreq);
  if(result)
    goto out;

  result = Curl_http_useragent(data);
  if(result)
    goto out;

  io = hyper_io_new();
  if(!io) {
    failf(data, "Couldn't create hyper IO");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  /* tell Hyper how to read/write network data */
  h->io_ctx.data = data;
  h->io_ctx.sockindex = FIRSTSOCKET;
  hyper_io_set_userdata(io, &h->io_ctx);
  hyper_io_set_read(io, Curl_hyper_recv);
  hyper_io_set_write(io, Curl_hyper_send);

  /* create an executor to poll futures */
  if(!h->exec) {
    h->exec = hyper_executor_new();
    if(!h->exec) {
      failf(data, "Couldn't create hyper executor");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  options = hyper_clientconn_options_new();
  if(!options) {
    failf(data, "Couldn't create hyper client options");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  if(conn->alpn == CURL_HTTP_VERSION_2) {
    failf(data, "ALPN protocol h2 not supported with Hyper");
    result = CURLE_UNSUPPORTED_PROTOCOL;
    goto out;
  }
  hyper_clientconn_options_set_preserve_header_case(options, 1);
  hyper_clientconn_options_set_preserve_header_order(options, 1);
  hyper_clientconn_options_http1_allow_multiline_headers(options, 1);

  hyper_clientconn_options_exec(options, h->exec);

  /* "Both the `io` and the `options` are consumed in this function call" */
  handshake = hyper_clientconn_handshake(io, options);
  if(!handshake) {
    failf(data, "Couldn't create hyper client handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  io = NULL;
  options = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, handshake)) {
    failf(data, "Couldn't hyper_executor_push the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  handshake = NULL; /* ownership passed on */

  task = hyper_executor_poll(h->exec);
  if(!task) {
    failf(data, "Couldn't hyper_executor_poll the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  client = hyper_task_value(task);
  hyper_task_free(task);

  req = hyper_request_new();
  if(!req) {
    failf(data, "Couldn't hyper_request_new");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!Curl_use_http_1_1plus(data, conn)) {
    if(HYPERE_OK != hyper_request_set_version(req,
                                              HYPER_HTTP_VERSION_1_0)) {
      failf(data, "error setting HTTP version");
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  if(hyper_request_set_method(req, (uint8_t *)method, strlen(method))) {
    failf(data, "error setting method");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = request_target(data, conn, method, req);
  if(result)
    goto out;

  headers = hyper_request_headers(req);
  if(!headers) {
    failf(data, "hyper_request_headers");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  rc = hyper_request_on_informational(req, http1xx_cb, data);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(data->state.aptr.host) {
    result = Curl_hyper_header(data, headers, data->state.aptr.host);
    if(result)
      goto out;
  }

#ifndef CURL_DISABLE_PROXY
  if(data->state.aptr.proxyuserpwd) {
    result = Curl_hyper_header(data, headers, data->state.aptr.proxyuserpwd);
    if(result)
      goto out;
  }
#endif

  if(data->state.aptr.userpwd) {
    result = Curl_hyper_header(data, headers, data->state.aptr.userpwd);
    if(result)
      goto out;
  }

  if((data->state.use_range && data->state.aptr.rangeline)) {
    result = Curl_hyper_header(data, headers, data->state.aptr.rangeline);
    if(result)
      goto out;
  }

  if(data->set.str[STRING_USERAGENT] &&
     *data->set.str[STRING_USERAGENT] &&
     data->state.aptr.uagent) {
    result = Curl_hyper_header(data, headers, data->state.aptr.uagent);
    if(result)
      goto out;
  }

  p_accept = Curl_checkheaders(data,
                               STRCONST("Accept")) ? NULL : "Accept: */*\r\n";
  if(p_accept) {
    result = Curl_hyper_header(data, headers, p_accept);
    if(result)
      goto out;
  }
  if(te) {
    result = Curl_hyper_header(data, headers, te);
    if(result)
      goto out;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(conn->bits.altused && !Curl_checkheaders(data, STRCONST("Alt-Used"))) {
    char *altused = aprintf("Alt-Used: %s:%d\r\n",
                            conn->conn_to_host.name, conn->conn_to_port);
    if(!altused) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    result = Curl_hyper_header(data, headers, altused);
    if(result)
      goto out;
    free(altused);
  }
#endif

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy &&
     !Curl_checkheaders(data, STRCONST("Proxy-Connection")) &&
     !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection"))) {
    result = Curl_hyper_header(data, headers, "Proxy-Connection: Keep-Alive");
    if(result)
      goto out;
  }
#endif

  Curl_safefree(data->state.aptr.ref);
  if(data->state.referer && !Curl_checkheaders(data, STRCONST("Referer"))) {
    data->state.aptr.ref = aprintf("Referer: %s\r\n", data->state.referer);
    if(!data->state.aptr.ref)
      result = CURLE_OUT_OF_MEMORY;
    else
      result = Curl_hyper_header(data, headers, data->state.aptr.ref);
    if(result)
      goto out;
  }

#ifdef HAVE_LIBZ
  /* we only consider transfer-encoding magic if libz support is built-in */
  result = Curl_transferencode(data);
  if(result)
    goto out;
  result = Curl_hyper_header(data, headers, data->state.aptr.te);
  if(result)
    goto out;
#endif

  if(!Curl_checkheaders(data, STRCONST("Accept-Encoding")) &&
     data->set.str[STRING_ENCODING]) {
    Curl_safefree(data->state.aptr.accept_encoding);
    data->state.aptr.accept_encoding =
      aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);
    if(!data->state.aptr.accept_encoding)
      result = CURLE_OUT_OF_MEMORY;
    else
      result = Curl_hyper_header(data, headers,
                                 data->state.aptr.accept_encoding);
    if(result)
      goto out;
  }
  else
    Curl_safefree(data->state.aptr.accept_encoding);

  result = cookies(data, conn, headers);
  if(result)
    goto out;

  if(!result && conn->handler->protocol&(CURLPROTO_WS|CURLPROTO_WSS))
    result = Curl_ws_request(data, headers);

  result = Curl_add_timecondition(data, headers);
  if(result)
    goto out;

  result = Curl_add_custom_headers(data, FALSE, headers);
  if(result)
    goto out;

  result = finalize_request(data, headers, req, httpreq);
  if(result)
    goto out;

  Curl_debug(data, CURLINFO_HEADER_OUT, (char *)"\r\n", 2);

  if(data->req.upload_chunky && data->req.authneg) {
    data->req.upload_chunky = TRUE;
  }
  else {
    data->req.upload_chunky = FALSE;
  }
  sendtask = hyper_clientconn_send(client, req);
  if(!sendtask) {
    failf(data, "hyper_clientconn_send");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  req = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, sendtask)) {
    failf(data, "Couldn't hyper_executor_push the send");
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  sendtask = NULL; /* ownership passed on */

  hyper_clientconn_free(client);
  client = NULL;

  if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) {
    /* HTTP GET/HEAD download */
    Curl_pgrsSetUploadSize(data, 0); /* nothing */
    result = Curl_req_set_upload_done(data);
    if(result)
      goto out;
  }

  Curl_xfer_setup1(data, CURL_XFER_SENDRECV, -1, TRUE);
  conn->datastream = Curl_hyper_stream;

  /* clear userpwd and proxyuserpwd to avoid reusing old credentials
   * from reused connections */
  Curl_safefree(data->state.aptr.userpwd);
#ifndef CURL_DISABLE_PROXY
  Curl_safefree(data->state.aptr.proxyuserpwd);
#endif

out:
  if(result) {
    if(io)
      hyper_io_free(io);
    if(options)
      hyper_clientconn_options_free(options);
    if(handshake)
      hyper_task_free(handshake);
    if(client)
      hyper_clientconn_free(client);
    if(req)
      hyper_request_free(req);
  }
  return result;
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
  if(h->send_body_waker) {
    hyper_waker_free(h->send_body_waker);
    h->send_body_waker = NULL;
  }
}

static CURLcode cr_hyper_unpause(struct Curl_easy *data,
                                 struct Curl_creader *reader)
{
  (void)reader;
  if(data->hyp.send_body_waker) {
    hyper_waker_wake(data->hyp.send_body_waker);
    data->hyp.send_body_waker = NULL;
  }
  return CURLE_OK;
}

/* Hyper client reader, handling unpausing */
static const struct Curl_crtype cr_hyper_protocol = {
  "cr-hyper",
  Curl_creader_def_init,
  Curl_creader_def_read,
  Curl_creader_def_close,
  Curl_creader_def_needs_rewind,
  Curl_creader_def_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_rewind,
  cr_hyper_unpause,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct Curl_creader)
};

static CURLcode cr_hyper_add(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &cr_hyper_protocol,
                               CURL_CR_PROTOCOL);
  if(!result)
    result = Curl_creader_add(data, reader);

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

#endif /* !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER) */
