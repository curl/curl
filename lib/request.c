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

#include "urldata.h"
#include "dynbuf.h"
#include "doh.h"
#include "multiif.h"
#include "progress.h"
#include "request.h"
#include "sendf.h"
#include "transfer.h"
#include "url.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

CURLcode Curl_req_init(struct SingleRequest *req)
{
  memset(req, 0, sizeof(*req));
  return CURLE_OK;
}

CURLcode Curl_req_start(struct SingleRequest *req,
                        struct Curl_easy *data)
{
  req->start = Curl_now();
  Curl_client_reset(data);
  if(!req->sendbuf_init) {
    Curl_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                    BUFQ_OPT_SOFT_LIMIT);
    req->sendbuf_init = TRUE;
  }
  else {
    Curl_bufq_reset(&req->sendbuf);
    if(data->set.upload_buffer_size != req->sendbuf.chunk_size) {
      Curl_bufq_free(&req->sendbuf);
      Curl_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                      BUFQ_OPT_SOFT_LIMIT);
    }
  }

  return CURLE_OK;
}

CURLcode Curl_req_done(struct SingleRequest *req,
                       struct Curl_easy *data, bool aborted)
{
  (void)req;
  if(!aborted)
    (void)Curl_req_flush(data);
  Curl_client_reset(data);
  return CURLE_OK;
}

void Curl_req_reset(struct SingleRequest *req, struct Curl_easy *data)
{
  struct bufq savebuf;
  bool save_init;

  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  Curl_client_reset(data);

#ifndef CURL_DISABLE_DOH
  if(req->doh) {
    Curl_close(&req->doh->probe[0].easy);
    Curl_close(&req->doh->probe[1].easy);
  }
#endif

  savebuf = req->sendbuf;
  save_init = req->sendbuf_init;

  memset(req, 0, sizeof(*req));
  data->req.size = data->req.maxdownload = -1;
  data->req.no_body = data->set.opt_no_body;
  if(save_init) {
    req->sendbuf = savebuf;
    req->sendbuf_init = save_init;
  }
}

void Curl_req_free(struct SingleRequest *req, struct Curl_easy *data)
{
  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  if(req->sendbuf_init)
    Curl_bufq_free(&req->sendbuf);
  Curl_client_reset(data);

#ifndef CURL_DISABLE_DOH
  if(req->doh) {
    Curl_close(&req->doh->probe[0].easy);
    Curl_close(&req->doh->probe[1].easy);
    Curl_dyn_free(&req->doh->probe[0].serverdoh);
    Curl_dyn_free(&req->doh->probe[1].serverdoh);
    curl_slist_free_all(req->doh->headers);
    Curl_safefree(req->doh);
  }
#endif
}

static CURLcode req_send(struct Curl_easy *data,
                         const char *buf, size_t blen,
                         size_t hds_len, size_t *pnwritten)
{
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
#ifdef CURLDEBUG
  {
    /* Allow debug builds to override this logic to force short initial
       sends
     */
    char *p = getenv("CURL_SMALLREQSEND");
    if(p) {
      size_t altsize = (size_t)strtoul(p, NULL, 10);
      if(altsize && altsize < blen)
        blen = altsize;
    }
  }
#endif
  /* Make sure this doesn't send more body bytes than what the max send
     speed says. The headers do not count to the max speed. */
  if(data->set.max_send_speed) {
    size_t body_bytes = blen - hds_len;
    if((curl_off_t)body_bytes > data->set.max_send_speed)
      blen = hds_len + (size_t)data->set.max_send_speed;
  }

  result = Curl_xfer_send(data, buf, blen, pnwritten);
  if(!result && *pnwritten) {
    if(hds_len)
      Curl_debug(data, CURLINFO_HEADER_OUT, (char *)buf,
                 CURLMIN(hds_len, *pnwritten));
    if(*pnwritten > hds_len) {
      size_t body_len = *pnwritten - hds_len;
      Curl_debug(data, CURLINFO_DATA_OUT, (char *)buf + hds_len, body_len);
      data->req.writebytecount += body_len;
      Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    }
  }
  return result;
}

static CURLcode req_send_buffer_flush(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  const unsigned char *buf;
  size_t blen;

  while(Curl_bufq_peek(&data->req.sendbuf, &buf, &blen)) {
    size_t nwritten, hds_len = CURLMIN(data->req.sendbuf_hds_len, blen);
    result = req_send(data, (const char *)buf, blen, hds_len, &nwritten);
    if(result)
      break;

    Curl_bufq_skip(&data->req.sendbuf, nwritten);
    if(hds_len) {
      data->req.sendbuf_hds_len -= CURLMIN(hds_len, nwritten);
      if(!data->req.sendbuf_hds_len) {
        /* all request headers sent */
        if(data->req.exp100 == EXP100_SENDING_REQUEST) {
          /* We are now waiting for a reply from the server or
           * a timeout on our side */
          data->req.exp100 = EXP100_AWAITING_CONTINUE;
          data->req.start100 = Curl_now();
          Curl_expire(data, data->set.expect_100_timeout, EXPIRE_100_TIMEOUT);
        }
      }
    }
    /* leave if we could not send all. Maybe network blocking or
     * speed limits on transfer */
    if(nwritten < blen)
      break;
  }
  return result;
}

CURLcode Curl_req_flush(struct Curl_easy *data)
{
  CURLcode result;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  if(!Curl_bufq_is_empty(&data->req.sendbuf)) {
    result = req_send_buffer_flush(data);
    if(result)
      return result;
    if(!Curl_bufq_is_empty(&data->req.sendbuf)) {
      return CURLE_AGAIN;
    }
  }
  return CURLE_OK;
}

#ifndef USE_HYPER

static CURLcode req_send_buffer_add(struct Curl_easy *data,
                                    const char *buf, size_t blen,
                                    size_t hds_len)
{
  CURLcode result = CURLE_OK;
  ssize_t n;
  n = Curl_bufq_write(&data->req.sendbuf,
                      (const unsigned char *)buf, blen, &result);
  if(n < 0)
    return result;
  /* We rely on a SOFTLIMIT on sendbuf, so it can take all data in */
  DEBUGASSERT((size_t)n == blen);
  data->req.sendbuf_hds_len += hds_len;
  return CURLE_OK;
}

static ssize_t add_from_client(void *reader_ctx,
                               unsigned char *buf, size_t buflen,
                               CURLcode *err)
{
  struct Curl_easy *data = reader_ctx;
  size_t nread;
  bool eos;

  *err = Curl_client_read(data, (char *)buf, buflen, &nread, &eos);
  if(*err)
    return -1;
  if(eos)
    data->req.eos_read = TRUE;
  return (ssize_t)nread;
}

CURLcode Curl_req_send(struct Curl_easy *data, struct dynbuf *buf)
{
  CURLcode result;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  /* We always buffer and send from there. The reason is that on
   * blocking, we can retry using the same memory address. This is
   * important for TLS libraries that expect this.
   * We *could* optimized for non-TLS transfers, but that would mean
   * separate code paths and seems not worth it. */
  result = req_send_buffer_add(data, Curl_dyn_ptr(buf), Curl_dyn_len(buf),
                               Curl_dyn_len(buf));
  if(result)
    return result;

  if((data->req.exp100 == EXP100_SEND_DATA) &&
     !Curl_bufq_is_full(&data->req.sendbuf)) {
    ssize_t nread = Curl_bufq_sipn(&data->req.sendbuf, 0,
                                   add_from_client, data, &result);
    if(nread < 0 && result != CURLE_AGAIN)
      return result;
  }

  result = req_send_buffer_flush(data);
  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  return result;
}
#endif /* !USE_HYPER */

bool Curl_req_want_send(struct Curl_easy *data)
{
  return data->req.sendbuf_init && !Curl_bufq_is_empty(&data->req.sendbuf);
}
