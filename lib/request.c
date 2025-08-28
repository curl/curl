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
#include "curlx/dynbuf.h"
#include "doh.h"
#include "multiif.h"
#include "progress.h"
#include "request.h"
#include "sendf.h"
#include "transfer.h"
#include "url.h"
#include "curlx/strparse.h"

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
  req->upload_aborted = FALSE;
  req->download_done = FALSE;
  req->eos_written = FALSE;
  req->eos_read = FALSE;
  req->eos_sent = FALSE;
  req->ignorebody = FALSE;
  req->shutdown = FALSE;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->header = FALSE;
  req->headerline = 0;
  req->headerbytecount = 0;
  req->allheadercount =  0;
  req->deductheadercount = 0;
  req->httpversion_sent = 0;
  req->httpversion = 0;
  req->sendbuf_hds_len = 0;

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
  req->start = curlx_now();
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
#ifndef CURL_DISABLE_DOH
  Curl_doh_close(data);
#endif
  return CURLE_OK;
}

void Curl_req_hard_reset(struct SingleRequest *req, struct Curl_easy *data)
{
  struct curltime t0 = {0, 0};

  Curl_safefree(req->newurl);
  Curl_client_reset(data);
  if(req->sendbuf_init)
    Curl_bufq_reset(&req->sendbuf);

#ifndef CURL_DISABLE_DOH
  Curl_doh_close(data);
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
  req->sendbuf_hds_len = 0;
  req->timeofdoc = 0;
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
  req->eos_sent = FALSE;
  req->rewind_read = FALSE;
  req->upload_done = FALSE;
  req->upload_aborted = FALSE;
  req->ignorebody = FALSE;
  req->http_bodyless = FALSE;
  req->chunk = FALSE;
  req->ignore_cl = FALSE;
  req->upload_chunky = FALSE;
  req->no_body = data->set.opt_no_body;
  req->authneg = FALSE;
  req->shutdown = FALSE;
}

void Curl_req_free(struct SingleRequest *req, struct Curl_easy *data)
{
  Curl_safefree(req->newurl);
  if(req->sendbuf_init)
    Curl_bufq_free(&req->sendbuf);
  Curl_client_cleanup(data);
}

static CURLcode xfer_send(struct Curl_easy *data,
                          const char *buf, size_t blen,
                          size_t hds_len, size_t *pnwritten)
{
  CURLcode result = CURLE_OK;
  bool eos = FALSE;

  *pnwritten = 0;
  DEBUGASSERT(hds_len <= blen);
#ifdef DEBUGBUILD
  {
    /* Allow debug builds to override this logic to force short initial
       sends */
    size_t body_len = blen - hds_len;
    if(body_len) {
      const char *p = getenv("CURL_SMALLREQSEND");
      if(p) {
        curl_off_t body_small;
        if(!curlx_str_number(&p, &body_small, body_len))
          blen = hds_len + (size_t)body_small;
      }
    }
  }
#endif
  /* Make sure this does not send more body bytes than what the max send
     speed says. The headers do not count to the max speed. */
  if(data->set.max_send_speed) {
    size_t body_bytes = blen - hds_len;
    if((curl_off_t)body_bytes > data->set.max_send_speed)
      blen = hds_len + (size_t)data->set.max_send_speed;
  }

  if(data->req.eos_read &&
    (Curl_bufq_is_empty(&data->req.sendbuf) ||
     Curl_bufq_len(&data->req.sendbuf) == blen)) {
    DEBUGF(infof(data, "sending last upload chunk of %zu bytes", blen));
    eos = TRUE;
  }
  result = Curl_xfer_send(data, buf, blen, eos, pnwritten);
  if(!result) {
    if(eos && (blen == *pnwritten))
      data->req.eos_sent = TRUE;
    if(*pnwritten) {
      if(hds_len)
        Curl_debug(data, CURLINFO_HEADER_OUT, buf,
                   CURLMIN(hds_len, *pnwritten));
      if(*pnwritten > hds_len) {
        size_t body_len = *pnwritten - hds_len;
        Curl_debug(data, CURLINFO_DATA_OUT, buf + hds_len, body_len);
        data->req.writebytecount += body_len;
        Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
      }
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
  data->req.keepon &= ~(KEEP_SEND|KEEP_SEND_TIMED); /* we are done sending */

  Curl_pgrsTime(data, TIMER_POSTRANSFER);
  Curl_creader_done(data, data->req.upload_aborted);

  if(data->req.upload_aborted) {
    Curl_bufq_reset(&data->req.sendbuf);
    if(data->req.writebytecount)
      infof(data, "abort upload after having sent %" FMT_OFF_T " bytes",
            data->req.writebytecount);
    else
      infof(data, "abort upload");
  }
  else if(data->req.writebytecount)
    infof(data, "upload completely sent off: %" FMT_OFF_T " bytes",
          data->req.writebytecount);
  else if(!data->req.download_done) {
    DEBUGASSERT(Curl_bufq_is_empty(&data->req.sendbuf));
    infof(data, Curl_creader_total_length(data) ?
          "We are completely uploaded and fine" :
          "Request completely sent off");
  }

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
      DEBUGF(infof(data, "Curl_req_flush(len=%zu) -> EAGAIN",
             Curl_bufq_len(&data->req.sendbuf)));
      return CURLE_AGAIN;
    }
  }
  else if(Curl_xfer_needs_flush(data)) {
    DEBUGF(infof(data, "Curl_req_flush(), xfer send_pending"));
    return Curl_xfer_flush(data);
  }

  if(data->req.eos_read && !data->req.eos_sent) {
    char tmp = 0;
    size_t nwritten;
    result = xfer_send(data, &tmp, 0, 0, &nwritten);
    if(result)
      return result;
    DEBUGASSERT(data->req.eos_sent);
  }

  if(!data->req.upload_done && data->req.eos_read && data->req.eos_sent) {
    DEBUGASSERT(Curl_bufq_is_empty(&data->req.sendbuf));
    if(data->req.shutdown) {
      bool done;
      result = Curl_xfer_send_shutdown(data, &done);
      if(result && data->req.shutdown_err_ignore) {
        infof(data, "Shutdown send direction error: %d. Broken server? "
              "Proceeding as if everything is ok.", result);
        result = CURLE_OK;
        done = TRUE;
      }

      if(result)
        return result;
      if(!done)
        return CURLE_AGAIN;
    }
    return req_set_upload_done(data);
  }
  return CURLE_OK;
}

static CURLcode add_from_client(void *reader_ctx,
                                unsigned char *buf, size_t buflen,
                                size_t *pnread)
{
  struct Curl_easy *data = reader_ctx;
  CURLcode result;
  bool eos;

  result = Curl_client_read(data, (char *)buf, buflen, pnread, &eos);
  if(!result && eos)
    data->req.eos_read = TRUE;
  return result;
}

static CURLcode req_send_buffer_add(struct Curl_easy *data,
                                    const char *buf, size_t blen,
                                    size_t hds_len)
{
  CURLcode result = CURLE_OK;
  size_t n;
  result = Curl_bufq_cwrite(&data->req.sendbuf, buf, blen, &n);
  if(result)
    return result;
  /* We rely on a SOFTLIMIT on sendbuf, so it can take all data in */
  DEBUGASSERT(n == blen);
  data->req.sendbuf_hds_len += hds_len;
  return CURLE_OK;
}

CURLcode Curl_req_send(struct Curl_easy *data, struct dynbuf *req,
                       unsigned char httpversion)
{
  CURLcode result;
  const char *buf;
  size_t blen, nwritten;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;

  data->req.httpversion_sent = httpversion;
  buf = curlx_dyn_ptr(req);
  blen = curlx_dyn_len(req);
  /* if the sendbuf is empty and the request without body and
   * the length to send fits info a sendbuf chunk, we send it directly.
   * If `blen` is larger then `chunk_size`, we can not. Because we
   * might have to retry a blocked send later from sendbuf and that
   * would result in retry sends with a shrunken length. That is trouble. */
  if(Curl_bufq_is_empty(&data->req.sendbuf) &&
     !Curl_creader_total_length(data) &&
     (blen <= data->req.sendbuf.chunk_size)) {
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

bool Curl_req_sendbuf_empty(struct Curl_easy *data)
{
  return !data->req.sendbuf_init || Curl_bufq_is_empty(&data->req.sendbuf);
}

bool Curl_req_want_send(struct Curl_easy *data)
{
  /* Not done and
   * - KEEP_SEND and not PAUSEd.
   * - or request has buffered data to send
   * - or transfer connection has pending data to send */
  return !data->req.done &&
         (((data->req.keepon & KEEP_SENDBITS) == KEEP_SEND) ||
           !Curl_req_sendbuf_empty(data) ||
           Curl_xfer_needs_flush(data));
}

bool Curl_req_done_sending(struct Curl_easy *data)
{
  return data->req.upload_done && !Curl_req_want_send(data);
}

CURLcode Curl_req_send_more(struct Curl_easy *data)
{
  CURLcode result;

  /* Fill our send buffer if more from client can be read. */
  if(!data->req.upload_aborted &&
     !data->req.eos_read &&
     !Curl_xfer_send_is_paused(data) &&
     !Curl_bufq_is_full(&data->req.sendbuf)) {
    size_t nread;
    result = Curl_bufq_sipn(&data->req.sendbuf, 0,
                            add_from_client, data, &nread);
    if(result && result != CURLE_AGAIN)
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
    /* no longer KEEP_SEND and KEEP_SEND_PAUSE */
    data->req.keepon &= ~KEEP_SENDBITS;
    return req_set_upload_done(data);
  }
  return CURLE_OK;
}

CURLcode Curl_req_stop_send_recv(struct Curl_easy *data)
{
  /* stop receiving and ALL sending as well, including PAUSE and HOLD.
   * We might still be paused on receive client writes though, so
   * keep those bits around. */
  data->req.keepon &= ~(KEEP_RECV|KEEP_SENDBITS);
  return Curl_req_abort_sending(data);
}
