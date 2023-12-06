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
#include "sendf.h"
#include "transfer.h"
#include "multiif.h"
#include "progress.h"
#include "content_encoding.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

typedef enum {
    USERDATA_NOT_SET = 0, /* for tasks with no userdata set; must be zero */
    USERDATA_RESP_BODY
} userdata_t;

size_t Curl_hyper_recv(void *userp, hyper_context *ctx,
                       uint8_t *buf, size_t buflen)
{
  struct Curl_easy *data = userp;
  struct connectdata *conn = data->conn;
  CURLcode result;
  ssize_t nread;
  DEBUGASSERT(conn);
  (void)ctx;

  DEBUGF(infof(data, "Curl_hyper_recv(%zu)", buflen));
  result = Curl_read(data, conn->sockfd, (char *)buf, buflen, &nread);
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
  struct Curl_easy *data = userp;
  struct connectdata *conn = data->conn;
  CURLcode result;
  ssize_t nwrote;

  DEBUGF(infof(data, "Curl_hyper_send(%zu)", buflen));
  result = Curl_write(data, conn->sockfd, (void *)buf, buflen, &nwrote);
  if(!result && !nwrote)
    result = CURLE_AGAIN;
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
    data->state.hresult = CURLE_OUT_OF_MEMORY;
    return HYPER_ITER_BREAK;
  }

  if(!data->req.bytecount)
    Curl_pgrsTime(data, TIMER_STARTTRANSFER);

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

  result = Curl_http_header(data, data->conn, headp);
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

  if(0 == k->bodywrites) {
    bool done = FALSE;
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
    if(data->state.expect100header) {
      Curl_expire_done(data, EXPIRE_100_TIMEOUT);
      if(data->req.httpcode < 400) {
        k->exp100 = EXP100_SEND_DATA;
        if(data->hyp.exp100_waker) {
          hyper_waker_wake(data->hyp.exp100_waker);
          data->hyp.exp100_waker = NULL;
        }
      }
      else { /* >= 4xx */
        k->exp100 = EXP100_FAILED;
      }
    }
    if(data->state.hconnect && (data->req.httpcode/100 != 2) &&
       data->state.authproxy.done) {
      done = TRUE;
      result = CURLE_OK;
    }
    else
      result = Curl_http_firstwrite(data, data->conn, &done);
    if(result || done) {
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

  if(data->state.hconnect)
    /* CONNECT */
    data->info.httpproxycode = http_status;
  else {
    conn->httpversion =
      http_version == HYPER_HTTP_VERSION_1_1 ? 11 :
      (http_version == HYPER_HTTP_VERSION_2 ? 20 : 10);
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
      failf(data, "hyperstream: couldn't pass blank header");
  }
  return result;
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
  const uint8_t *reasonp;
  size_t reason_len;
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  (void)conn;

  if(k->exp100 > EXP100_SEND_DATA) {
    struct curltime now = Curl_now();
    timediff_t ms = Curl_timediff(now, k->start100);
    if(ms >= data->set.expect_100_timeout) {
      /* we've waited long enough, continue anyway */
      k->exp100 = EXP100_SEND_DATA;
      k->keepon |= KEEP_SEND;
      Curl_expire_done(data, EXPIRE_100_TIMEOUT);
      infof(data, "Done waiting for 100-continue");
      if(data->hyp.exp100_waker) {
        hyper_waker_wake(data->hyp.exp100_waker);
        data->hyp.exp100_waker = NULL;
      }
    }
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

  *done = FALSE;
  do {
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
          break;
        case HYPERE_UNEXPECTED_EOF:
          if(!data->req.bytecount)
            result = CURLE_GOT_NOTHING;
          else
            result = CURLE_RECV_ERROR;
          break;
        case HYPERE_INVALID_PEER_MESSAGE:
          /* bump headerbytecount to avoid the count remaining at zero and
             appearing to not having read anything from the peer at all */
          data->req.headerbytecount++;
          result = CURLE_UNSUPPORTED_PROTOCOL; /* maybe */
          break;
        default:
          result = CURLE_RECV_ERROR;
          break;
        }
      }
      *done = TRUE;
      hyper_error_free(hypererr);
      break;
    }
    else if(t == HYPER_TASK_EMPTY) {
      void *userdata = hyper_task_userdata(task);
      hyper_task_free(task);
      if((userdata_t)userdata == USERDATA_RESP_BODY) {
        /* end of transfer */
        *done = TRUE;
        infof(data, "hyperstream is done");
        if(!k->bodywrites) {
          /* hyper doesn't always call the body write callback */
          bool stilldone;
          result = Curl_http_firstwrite(data, data->conn, &stilldone);
        }
        break;
      }
      else {
        /* A background task for hyper; ignore */
        continue;
      }
    }

    DEBUGASSERT(HYPER_TASK_RESPONSE);

    resp = hyper_task_value(task);
    hyper_task_free(task);

    *didwhat = KEEP_RECV;
    if(!resp) {
      failf(data, "hyperstream: couldn't get response");
      return CURLE_RECV_ERROR;
    }

    http_status = hyper_response_status(resp);
    http_version = hyper_response_version(resp);
    reasonp = hyper_response_reason_phrase(resp);
    reason_len = hyper_response_reason_phrase_len(resp);

    if(http_status == 417 && data->state.expect100header) {
      infof(data, "Got 417 while waiting for a 100");
      data->state.disableexpect = TRUE;
      data->req.newurl = strdup(data->state.url);
      Curl_done_sending(data, k);
    }

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

    result = empty_header(data);
    if(result)
      break;

    k->deductheadercount =
      (100 <= http_status && 199 >= http_status)?k->headerbytecount:0;
#ifdef USE_WEBSOCKETS
    if(k->upgr101 == UPGR101_WS) {
      if(http_status == 101) {
        /* verify the response */
        result = Curl_ws_accept(data, NULL, 0);
        if(result)
          return result;
      }
      else {
        failf(data, "Expected 101, got %u", k->httpcode);
        result = CURLE_HTTP_RETURNED_ERROR;
        break;
      }
    }
#endif

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
    hyper_task_set_userdata(foreach, (void *)USERDATA_RESP_BODY);
    if(HYPERE_OK != hyper_executor_push(h->exec, foreach)) {
      failf(data, "Couldn't hyper_executor_push the body-foreach");
      result = CURLE_OUT_OF_MEMORY;
      break;
    }

    hyper_response_free(resp);
    resp = NULL;
  } while(1);
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

static int uploadpostfields(void *userdata, hyper_context *ctx,
                            hyper_buf **chunk)
{
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  (void)ctx;
  if(data->req.exp100 > EXP100_SEND_DATA) {
    if(data->req.exp100 == EXP100_FAILED)
      return HYPER_POLL_ERROR;

    /* still waiting confirmation */
    if(data->hyp.exp100_waker)
      hyper_waker_free(data->hyp.exp100_waker);
    data->hyp.exp100_waker = hyper_context_waker(ctx);
    return HYPER_POLL_PENDING;
  }
  if(data->req.upload_done)
    *chunk = NULL; /* nothing more to deliver */
  else {
    /* send everything off in a single go */
    hyper_buf *copy = hyper_buf_copy(data->set.postfields,
                                     (size_t)data->req.p.http->postsize);
    if(copy)
      *chunk = copy;
    else {
      data->state.hresult = CURLE_OUT_OF_MEMORY;
      return HYPER_POLL_ERROR;
    }
    /* increasing the writebytecount here is a little premature but we
       don't know exactly when the body is sent */
    data->req.writebytecount += (size_t)data->req.p.http->postsize;
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    data->req.upload_done = TRUE;
  }
  return HYPER_POLL_READY;
}

static int uploadstreamed(void *userdata, hyper_context *ctx,
                          hyper_buf **chunk)
{
  size_t fillcount;
  struct Curl_easy *data = (struct Curl_easy *)userdata;
  struct connectdata *conn = (struct connectdata *)data->conn;
  CURLcode result;
  (void)ctx;

  if(data->req.exp100 > EXP100_SEND_DATA) {
    if(data->req.exp100 == EXP100_FAILED)
      return HYPER_POLL_ERROR;

    /* still waiting confirmation */
    if(data->hyp.exp100_waker)
      hyper_waker_free(data->hyp.exp100_waker);
    data->hyp.exp100_waker = hyper_context_waker(ctx);
    return HYPER_POLL_PENDING;
  }

  if(data->req.upload_chunky && conn->bits.authneg) {
    fillcount = 0;
    data->req.upload_chunky = FALSE;
    result = CURLE_OK;
  }
  else {
    result = Curl_fillreadbuffer(data, data->set.upload_buffer_size,
                                 &fillcount);
  }
  if(result) {
    data->state.hresult = result;
    return HYPER_POLL_ERROR;
  }
  if(!fillcount) {
    if((data->req.keepon & KEEP_SEND_PAUSE) != KEEP_SEND_PAUSE)
      /* done! */
      *chunk = NULL;
    else {
      /* paused, save a waker */
      if(data->hyp.send_body_waker)
        hyper_waker_free(data->hyp.send_body_waker);
      data->hyp.send_body_waker = hyper_context_waker(ctx);
      return HYPER_POLL_PENDING;
    }
  }
  else {
    hyper_buf *copy = hyper_buf_copy((uint8_t *)data->state.ulbuf, fillcount);
    if(copy)
      *chunk = copy;
    else {
      data->state.hresult = CURLE_OUT_OF_MEMORY;
      return HYPER_POLL_ERROR;
    }
    /* increasing the writebytecount here is a little premature but we
       don't know exactly when the body is sent */
    data->req.writebytecount += fillcount;
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
  }
  return HYPER_POLL_READY;
}

/*
 * bodysend() sets up headers in the outgoing request for an HTTP transfer that
 * sends a body
 */

static CURLcode bodysend(struct Curl_easy *data,
                         struct connectdata *conn,
                         hyper_headers *headers,
                         hyper_request *hyperreq,
                         Curl_HttpReq httpreq)
{
  struct HTTP *http = data->req.p.http;
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
      if(result) {
        hyper_body_free(body);
        return result;
      }
      /* init the "upload from here" pointer */
      data->req.upload_fromhere = data->state.ulbuf;
      hyper_body_set_data_func(body, uploadstreamed);
    }
    if(HYPERE_OK != hyper_request_set_body(hyperreq, body)) {
      /* fail */
      result = CURLE_OUT_OF_MEMORY;
    }
  }
  http->sending = HTTPSEND_BODY;
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
      failf(data, "hyperstream: couldn't get 1xx response headers");
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
  Curl_client_cleanup(data);

  infof(data, "Time for the Hyper dance");
  memset(h, 0, sizeof(struct hyptransfer));

  result = Curl_http_host(data, conn);
  if(result)
    return result;

  Curl_http_method(data, conn, &method, &httpreq);

  DEBUGASSERT(data->req.bytecount ==  0);

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
    result = CURLE_OUT_OF_MEMORY;
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
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
  }

  options = hyper_clientconn_options_new();
  if(!options) {
    failf(data, "Couldn't create hyper client options");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  if(conn->alpn == CURL_HTTP_VERSION_2) {
    failf(data, "ALPN protocol h2 not supported with Hyper");
    result = CURLE_UNSUPPORTED_PROTOCOL;
    goto error;
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
    goto error;
  }
  io = NULL;
  options = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, handshake)) {
    failf(data, "Couldn't hyper_executor_push the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  handshake = NULL; /* ownership passed on */

  task = hyper_executor_poll(h->exec);
  if(!task) {
    failf(data, "Couldn't hyper_executor_poll the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  client = hyper_task_value(task);
  hyper_task_free(task);

  req = hyper_request_new();
  if(!req) {
    failf(data, "Couldn't hyper_request_new");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  if(!Curl_use_http_1_1plus(data, conn)) {
    if(HYPERE_OK != hyper_request_set_version(req,
                                              HYPER_HTTP_VERSION_1_0)) {
      failf(data, "error setting HTTP version");
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
  }
  else {
    if(!data->state.disableexpect) {
      data->state.expect100header = TRUE;
    }
  }

  if(hyper_request_set_method(req, (uint8_t *)method, strlen(method))) {
    failf(data, "error setting method");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  result = request_target(data, conn, method, req);
  if(result)
    goto error;

  headers = hyper_request_headers(req);
  if(!headers) {
    failf(data, "hyper_request_headers");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  rc = hyper_request_on_informational(req, http1xx_cb, data);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  result = Curl_http_body(data, conn, httpreq, &te);
  if(result)
    goto error;

  if(data->state.aptr.host) {
    result = Curl_hyper_header(data, headers, data->state.aptr.host);
    if(result)
      goto error;
  }

  if(data->state.aptr.proxyuserpwd) {
    result = Curl_hyper_header(data, headers, data->state.aptr.proxyuserpwd);
    if(result)
      goto error;
  }

  if(data->state.aptr.userpwd) {
    result = Curl_hyper_header(data, headers, data->state.aptr.userpwd);
    if(result)
      goto error;
  }

  if((data->state.use_range && data->state.aptr.rangeline)) {
    result = Curl_hyper_header(data, headers, data->state.aptr.rangeline);
    if(result)
      goto error;
  }

  if(data->set.str[STRING_USERAGENT] &&
     *data->set.str[STRING_USERAGENT] &&
     data->state.aptr.uagent) {
    result = Curl_hyper_header(data, headers, data->state.aptr.uagent);
    if(result)
      goto error;
  }

  p_accept = Curl_checkheaders(data,
                               STRCONST("Accept"))?NULL:"Accept: */*\r\n";
  if(p_accept) {
    result = Curl_hyper_header(data, headers, p_accept);
    if(result)
      goto error;
  }
  if(te) {
    result = Curl_hyper_header(data, headers, te);
    if(result)
      goto error;
  }

#ifndef CURL_DISABLE_ALTSVC
  if(conn->bits.altused && !Curl_checkheaders(data, STRCONST("Alt-Used"))) {
    char *altused = aprintf("Alt-Used: %s:%d\r\n",
                            conn->conn_to_host.name, conn->conn_to_port);
    if(!altused) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    result = Curl_hyper_header(data, headers, altused);
    if(result)
      goto error;
    free(altused);
  }
#endif

#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy &&
     !Curl_checkheaders(data, STRCONST("Proxy-Connection")) &&
     !Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection"))) {
    result = Curl_hyper_header(data, headers, "Proxy-Connection: Keep-Alive");
    if(result)
      goto error;
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
      goto error;
  }

#ifdef HAVE_LIBZ
  /* we only consider transfer-encoding magic if libz support is built-in */
  result = Curl_transferencode(data);
  if(result)
    goto error;
  result = Curl_hyper_header(data, headers, data->state.aptr.te);
  if(result)
    goto error;
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
      goto error;
  }
  else
    Curl_safefree(data->state.aptr.accept_encoding);

  result = cookies(data, conn, headers);
  if(result)
    goto error;

  if(!result && conn->handler->protocol&(CURLPROTO_WS|CURLPROTO_WSS))
    result = Curl_ws_request(data, headers);

  result = Curl_add_timecondition(data, headers);
  if(result)
    goto error;

  result = Curl_add_custom_headers(data, FALSE, headers);
  if(result)
    goto error;

  result = bodysend(data, conn, headers, req, httpreq);
  if(result)
    goto error;

  Curl_debug(data, CURLINFO_HEADER_OUT, (char *)"\r\n", 2);

  if(data->req.upload_chunky && conn->bits.authneg) {
    data->req.upload_chunky = TRUE;
  }
  else {
    data->req.upload_chunky = FALSE;
  }
  sendtask = hyper_clientconn_send(client, req);
  if(!sendtask) {
    failf(data, "hyper_clientconn_send");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  req = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, sendtask)) {
    failf(data, "Couldn't hyper_executor_push the send");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  sendtask = NULL; /* ownership passed on */

  hyper_clientconn_free(client);
  client = NULL;

  if((httpreq == HTTPREQ_GET) || (httpreq == HTTPREQ_HEAD)) {
    /* HTTP GET/HEAD download */
    Curl_pgrsSetUploadSize(data, 0); /* nothing */
    Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);
  }
  conn->datastream = Curl_hyper_stream;
  if(data->state.expect100header)
    /* Timeout count starts now since with Hyper we don't know exactly when
       the full request has been sent. */
    data->req.start100 = Curl_now();

  /* clear userpwd and proxyuserpwd to avoid reusing old credentials
   * from reused connections */
  Curl_safefree(data->state.aptr.userpwd);
  Curl_safefree(data->state.aptr.proxyuserpwd);
  return CURLE_OK;
error:
  DEBUGASSERT(result);
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
  if(h->exp100_waker) {
    hyper_waker_free(h->exp100_waker);
    h->exp100_waker = NULL;
  }
}

#endif /* !defined(CURL_DISABLE_HTTP) && defined(USE_HYPER) */
