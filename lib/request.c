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
  Curl_cw_reset(data);
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
  Curl_cw_reset(data);
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
  Curl_cw_reset(data);

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
  Curl_cw_reset(data);

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
    if(hds_len)
      data->req.sendbuf_hds_len -= CURLMIN(hds_len, nwritten);
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

CURLcode Curl_req_send(struct Curl_easy *data,
                       const char *buf, size_t blen,
                       size_t hds_len)
{
  CURLcode result;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  /* We always buffer and send from there. The reason is that on
   * blocking, we can retry using the same memory address. This is
   * important for TLS libraries that expect this.
   * We *could* optimized for non-TLS transfers, but that would mean
   * separate code paths and seems not worth it. */
  result = req_send_buffer_add(data, buf, blen, hds_len);
  if(result)
    return result;
  result = req_send_buffer_flush(data);
  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  return result;
}

bool Curl_req_want_send(struct Curl_easy *data)
{
  return data->req.sendbuf_init && !Curl_bufq_is_empty(&data->req.sendbuf);
}
