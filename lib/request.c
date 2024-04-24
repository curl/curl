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
#include "cfilters.h"
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

void Curl_req_init(struct SingleRequest *req)
{
  memset(req, 0, sizeof(*req));
}

CURLcode Curl_req_soft_reset(struct SingleRequest *req,
                             struct Curl_easy *data)
{
  CURLcode result;

  req->done = FALSE;
  req->upload_done = FALSE;
  req->download_done = FALSE;
  req->ignorebody = FALSE;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->header = TRUE; /* assume header */
  req->headerline = 0;
  req->headerbytecount = 0;
  req->allheadercount =  0;
  req->deductheadercount = 0;

  result = Curl_client_start(data);
  if(result)
    return result;

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

CURLcode Curl_req_start(struct SingleRequest *req,
                        struct Curl_easy *data)
{
  req->start = Curl_now();
  return Curl_req_soft_reset(req, data);
}

static CURLcode req_flush(struct Curl_easy *data);

CURLcode Curl_req_done(struct SingleRequest *req,
                       struct Curl_easy *data, bool aborted)
{
  (void)req;
  if(!aborted)
    (void)req_flush(data);
  Curl_client_reset(data);
  return CURLE_OK;
}

void Curl_req_hard_reset(struct SingleRequest *req, struct Curl_easy *data)
{
  struct curltime t0 = {0, 0};

  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  Curl_client_reset(data);
  if(req->sendbuf_init)
    Curl_bufq_reset(&req->sendbuf);

#ifndef CURL_DISABLE_DOH
  if(req->doh) {
    Curl_close(&req->doh->probe[0].easy);
    Curl_close(&req->doh->probe[1].easy);
  }
#endif
  /* Can no longer memset() this struct as we need to keep some state */
  req->size = -1;
  req->maxdownload = -1;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->start = t0;
  req->headerbytecount = 0;
  req->allheadercount =  0;
  req->deductheadercount = 0;
  req->headerline = 0;
  req->offset = 0;
  req->httpcode = 0;
  req->keepon = 0;
  req->upgr101 = UPGR101_INIT;
  req->timeofdoc = 0;
  req->bodywrites = 0;
  req->location = NULL;
  req->newurl = NULL;
#ifndef CURL_DISABLE_COOKIES
  req->setcookies = 0;
#endif
  req->header = FALSE;
  req->content_range = FALSE;
  req->download_done = FALSE;
  req->eos_written = FALSE;
  req->eos_read = FALSE;
  req->upload_done = FALSE;
  req->upload_aborted = FALSE;
  req->ignorebody = FALSE;
  req->http_bodyless = FALSE;
  req->chunk = FALSE;
  req->ignore_cl = FALSE;
  req->upload_chunky = FALSE;
  req->getheader = FALSE;
  req->no_body = data->set.opt_no_body;
  req->authneg = FALSE;
}

void Curl_req_free(struct SingleRequest *req, struct Curl_easy *data)
{
  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Curl_safefree(req->p.http);
  Curl_safefree(req->newurl);
  if(req->sendbuf_init)
    Curl_bufq_free(&req->sendbuf);
  Curl_client_cleanup(data);

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

static CURLcode xfer_send(struct Curl_easy *data,
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
    result = xfer_send(data, (const char *)buf, blen, hds_len, &nwritten);
    if(result)
      break;

    Curl_bufq_skip(&data->req.sendbuf, nwritten);
    if(hds_len) {
      data->req.sendbuf_hds_len -= CURLMIN(hds_len, nwritten);
    }
    /* leave if we could not send all. Maybe network blocking or
     * speed limits on transfer */
    if(nwritten < blen)
      break;
  }
  return result;
}

static CURLcode req_set_upload_done(struct Curl_easy *data)
{
  DEBUGASSERT(!data->req.upload_done);
  data->req.upload_done = TRUE;
  data->req.keepon &= ~(KEEP_SEND|KEEP_SEND_TIMED); /* we're done sending */

  Curl_creader_done(data, data->req.upload_aborted);

  if(data->req.upload_aborted) {
    if(data->req.writebytecount)
      infof(data, "abort upload after having sent %" CURL_FORMAT_CURL_OFF_T
            " bytes", data->req.writebytecount);
    else
      infof(data, "abort upload");
  }
  else if(data->req.writebytecount)
    infof(data, "upload completely sent off: %" CURL_FORMAT_CURL_OFF_T
          " bytes", data->req.writebytecount);
  else if(!data->req.download_done)
    infof(data, Curl_creader_total_length(data)?
                "We are completely uploaded and fine" :
                "Request completely sent off");

  return Curl_xfer_send_close(data);
}

static CURLcode req_flush(struct Curl_easy *data)
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

  if(!data->req.upload_done && data->req.eos_read &&
     Curl_bufq_is_empty(&data->req.sendbuf)) {
    return req_set_upload_done(data);
  }
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

CURLcode Curl_req_send(struct Curl_easy *data, struct dynbuf *req)
{
  CURLcode result;
  const char *buf;
  size_t blen, nwritten;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  buf = Curl_dyn_ptr(req);
  blen = Curl_dyn_len(req);
  if(!Curl_creader_total_length(data)) {
    /* Request without body. Try to send directly from the buf given. */
    data->req.eos_read = TRUE;
    result = xfer_send(data, buf, blen, blen, &nwritten);
    if(result)
      return result;
    buf += nwritten;
    blen -= nwritten;
  }

  if(blen) {
    /* Either we have a request body, or we could not send the complete
     * request in one go. Buffer the remainder and try to add as much
     * body bytes as room is left in the buffer. Then flush. */
    result = req_send_buffer_add(data, buf, blen, blen);
    if(result)
      return result;

    return Curl_req_send_more(data);
  }
  return CURLE_OK;
}
#endif /* !USE_HYPER */

bool Curl_req_want_send(struct Curl_easy *data)
{
  return data->req.sendbuf_init && !Curl_bufq_is_empty(&data->req.sendbuf);
}

bool Curl_req_done_sending(struct Curl_easy *data)
{
  if(data->req.upload_done) {
    DEBUGASSERT(Curl_bufq_is_empty(&data->req.sendbuf));
    return TRUE;
  }
  return FALSE;
}

CURLcode Curl_req_send_more(struct Curl_easy *data)
{
  CURLcode result;

  /* Fill our send buffer if more from client can be read. */
  if(!data->req.eos_read && !Curl_bufq_is_full(&data->req.sendbuf)) {
    ssize_t nread = Curl_bufq_sipn(&data->req.sendbuf, 0,
                                   add_from_client, data, &result);
    if(nread < 0 && result != CURLE_AGAIN)
      return result;
  }

  result = req_flush(data);
  if(result == CURLE_AGAIN)
    result = CURLE_OK;

  return result;
}

CURLcode Curl_req_abort_sending(struct Curl_easy *data)
{
  if(!data->req.upload_done) {
    Curl_bufq_reset(&data->req.sendbuf);
    data->req.upload_aborted = TRUE;
    return req_set_upload_done(data);
  }
  return CURLE_OK;
}
