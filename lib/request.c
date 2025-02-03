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
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

void Fetch_req_init(struct SingleRequest *req)
{
  memset(req, 0, sizeof(*req));
}

FETCHcode Fetch_req_soft_reset(struct SingleRequest *req,
                              struct Fetch_easy *data)
{
  FETCHcode result;

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
  req->header = TRUE; /* assume header */
  req->headerline = 0;
  req->headerbytecount = 0;
  req->allheadercount = 0;
  req->deductheadercount = 0;
  req->httpversion_sent = 0;
  req->httpversion = 0;
  result = Fetch_client_start(data);
  if (result)
    return result;

  if (!req->sendbuf_init)
  {
    Fetch_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                    BUFQ_OPT_SOFT_LIMIT);
    req->sendbuf_init = TRUE;
  }
  else
  {
    Fetch_bufq_reset(&req->sendbuf);
    if (data->set.upload_buffer_size != req->sendbuf.chunk_size)
    {
      Fetch_bufq_free(&req->sendbuf);
      Fetch_bufq_init2(&req->sendbuf, data->set.upload_buffer_size, 1,
                      BUFQ_OPT_SOFT_LIMIT);
    }
  }

  return FETCHE_OK;
}

FETCHcode Fetch_req_start(struct SingleRequest *req,
                         struct Fetch_easy *data)
{
  req->start = Fetch_now();
  return Fetch_req_soft_reset(req, data);
}

static FETCHcode req_flush(struct Fetch_easy *data);

FETCHcode Fetch_req_done(struct SingleRequest *req,
                        struct Fetch_easy *data, bool aborted)
{
  (void)req;
  if (!aborted)
    (void)req_flush(data);
  Fetch_client_reset(data);
#ifndef FETCH_DISABLE_DOH
  Fetch_doh_close(data);
#endif
  return FETCHE_OK;
}

void Fetch_req_hard_reset(struct SingleRequest *req, struct Fetch_easy *data)
{
  struct fetchtime t0 = {0, 0};

  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Fetch_safefree(req->p.ftp);
  Fetch_safefree(req->newurl);
  Fetch_client_reset(data);
  if (req->sendbuf_init)
    Fetch_bufq_reset(&req->sendbuf);

#ifndef FETCH_DISABLE_DOH
  Fetch_doh_close(data);
#endif
  /* Can no longer memset() this struct as we need to keep some state */
  req->size = -1;
  req->maxdownload = -1;
  req->bytecount = 0;
  req->writebytecount = 0;
  req->start = t0;
  req->headerbytecount = 0;
  req->allheadercount = 0;
  req->deductheadercount = 0;
  req->headerline = 0;
  req->offset = 0;
  req->httpcode = 0;
  req->keepon = 0;
  req->upgr101 = UPGR101_INIT;
  req->timeofdoc = 0;
  req->location = NULL;
  req->newurl = NULL;
#ifndef FETCH_DISABLE_COOKIES
  req->setcookies = 0;
#endif
  req->header = FALSE;
  req->content_range = FALSE;
  req->download_done = FALSE;
  req->eos_written = FALSE;
  req->eos_read = FALSE;
  req->eos_sent = FALSE;
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
  req->shutdown = FALSE;
}

void Fetch_req_free(struct SingleRequest *req, struct Fetch_easy *data)
{
  /* This is a bit ugly. `req->p` is a union and we assume we can
   * free this safely without leaks. */
  Fetch_safefree(req->p.ftp);
  Fetch_safefree(req->newurl);
  if (req->sendbuf_init)
    Fetch_bufq_free(&req->sendbuf);
  Fetch_client_cleanup(data);

#ifndef FETCH_DISABLE_DOH
  Fetch_doh_cleanup(data);
#endif
}

static FETCHcode xfer_send(struct Fetch_easy *data,
                           const char *buf, size_t blen,
                           size_t hds_len, size_t *pnwritten)
{
  FETCHcode result = FETCHE_OK;
  bool eos = FALSE;

  *pnwritten = 0;
  DEBUGASSERT(hds_len <= blen);
#ifdef DEBUGBUILD
  {
    /* Allow debug builds to override this logic to force short initial
       sends */
    size_t body_len = blen - hds_len;
    char *p = getenv("FETCH_SMALLREQSEND");
    if (p)
    {
      size_t body_small = (size_t)strtoul(p, NULL, 10);
      if (body_small && body_small < body_len)
        blen = hds_len + body_small;
    }
  }
#endif
  /* Make sure this does not send more body bytes than what the max send
     speed says. The headers do not count to the max speed. */
  if (data->set.max_send_speed)
  {
    size_t body_bytes = blen - hds_len;
    if ((fetch_off_t)body_bytes > data->set.max_send_speed)
      blen = hds_len + (size_t)data->set.max_send_speed;
  }

  if (data->req.eos_read &&
      (Fetch_bufq_is_empty(&data->req.sendbuf) ||
       Fetch_bufq_len(&data->req.sendbuf) == blen))
  {
    DEBUGF(infof(data, "sending last upload chunk of %zu bytes", blen));
    eos = TRUE;
  }
  result = Fetch_xfer_send(data, buf, blen, eos, pnwritten);
  if (!result)
  {
    if (eos && (blen == *pnwritten))
      data->req.eos_sent = TRUE;
    if (*pnwritten)
    {
      if (hds_len)
        Fetch_debug(data, FETCHINFO_HEADER_OUT, (char *)buf,
                   FETCHMIN(hds_len, *pnwritten));
      if (*pnwritten > hds_len)
      {
        size_t body_len = *pnwritten - hds_len;
        Fetch_debug(data, FETCHINFO_DATA_OUT, (char *)buf + hds_len, body_len);
        data->req.writebytecount += body_len;
        Fetch_pgrsSetUploadCounter(data, data->req.writebytecount);
      }
    }
  }
  return result;
}

static FETCHcode req_send_buffer_flush(struct Fetch_easy *data)
{
  FETCHcode result = FETCHE_OK;
  const unsigned char *buf;
  size_t blen;

  while (Fetch_bufq_peek(&data->req.sendbuf, &buf, &blen))
  {
    size_t nwritten, hds_len = FETCHMIN(data->req.sendbuf_hds_len, blen);
    result = xfer_send(data, (const char *)buf, blen, hds_len, &nwritten);
    if (result)
      break;

    Fetch_bufq_skip(&data->req.sendbuf, nwritten);
    if (hds_len)
    {
      data->req.sendbuf_hds_len -= FETCHMIN(hds_len, nwritten);
    }
    /* leave if we could not send all. Maybe network blocking or
     * speed limits on transfer */
    if (nwritten < blen)
      break;
  }
  return result;
}

static FETCHcode req_set_upload_done(struct Fetch_easy *data)
{
  DEBUGASSERT(!data->req.upload_done);
  data->req.upload_done = TRUE;
  data->req.keepon &= ~(KEEP_SEND | KEEP_SEND_TIMED); /* we are done sending */

  Fetch_pgrsTime(data, TIMER_POSTRANSFER);
  Fetch_creader_done(data, data->req.upload_aborted);

  if (data->req.upload_aborted)
  {
    Fetch_bufq_reset(&data->req.sendbuf);
    if (data->req.writebytecount)
      infof(data, "abort upload after having sent %" FMT_OFF_T " bytes",
            data->req.writebytecount);
    else
      infof(data, "abort upload");
  }
  else if (data->req.writebytecount)
    infof(data, "upload completely sent off: %" FMT_OFF_T " bytes",
          data->req.writebytecount);
  else if (!data->req.download_done)
  {
    DEBUGASSERT(Fetch_bufq_is_empty(&data->req.sendbuf));
    infof(data, Fetch_creader_total_length(data) ? "We are completely uploaded and fine" : "Request completely sent off");
  }

  return Fetch_xfer_send_close(data);
}

static FETCHcode req_flush(struct Fetch_easy *data)
{
  FETCHcode result;

  if (!data || !data->conn)
    return FETCHE_FAILED_INIT;

  if (!Fetch_bufq_is_empty(&data->req.sendbuf))
  {
    result = req_send_buffer_flush(data);
    if (result)
      return result;
    if (!Fetch_bufq_is_empty(&data->req.sendbuf))
    {
      DEBUGF(infof(data, "Fetch_req_flush(len=%zu) -> EAGAIN",
                   Fetch_bufq_len(&data->req.sendbuf)));
      return FETCHE_AGAIN;
    }
  }
  else if (Fetch_xfer_needs_flush(data))
  {
    DEBUGF(infof(data, "Fetch_req_flush(), xfer send_pending"));
    return Fetch_xfer_flush(data);
  }

  if (data->req.eos_read && !data->req.eos_sent)
  {
    char tmp;
    size_t nwritten;
    result = xfer_send(data, &tmp, 0, 0, &nwritten);
    if (result)
      return result;
    DEBUGASSERT(data->req.eos_sent);
  }

  if (!data->req.upload_done && data->req.eos_read && data->req.eos_sent)
  {
    DEBUGASSERT(Fetch_bufq_is_empty(&data->req.sendbuf));
    if (data->req.shutdown)
    {
      bool done;
      result = Fetch_xfer_send_shutdown(data, &done);
      if (result && data->req.shutdown_err_ignore)
      {
        infof(data, "Shutdown send direction error: %d. Broken server? "
                    "Proceeding as if everything is ok.",
              result);
        result = FETCHE_OK;
        done = TRUE;
      }

      if (result)
        return result;
      if (!done)
        return FETCHE_AGAIN;
    }
    return req_set_upload_done(data);
  }
  return FETCHE_OK;
}

static ssize_t add_from_client(void *reader_ctx,
                               unsigned char *buf, size_t buflen,
                               FETCHcode *err)
{
  struct Fetch_easy *data = reader_ctx;
  size_t nread;
  bool eos;

  *err = Fetch_client_read(data, (char *)buf, buflen, &nread, &eos);
  if (*err)
    return -1;
  if (eos)
    data->req.eos_read = TRUE;
  return (ssize_t)nread;
}

static FETCHcode req_send_buffer_add(struct Fetch_easy *data,
                                     const char *buf, size_t blen,
                                     size_t hds_len)
{
  FETCHcode result = FETCHE_OK;
  ssize_t n;
  n = Fetch_bufq_write(&data->req.sendbuf,
                      (const unsigned char *)buf, blen, &result);
  if (n < 0)
    return result;
  /* We rely on a SOFTLIMIT on sendbuf, so it can take all data in */
  DEBUGASSERT((size_t)n == blen);
  data->req.sendbuf_hds_len += hds_len;
  return FETCHE_OK;
}

FETCHcode Fetch_req_send(struct Fetch_easy *data, struct dynbuf *req,
                        unsigned char httpversion)
{
  FETCHcode result;
  const char *buf;
  size_t blen, nwritten;

  if (!data || !data->conn)
    return FETCHE_FAILED_INIT;

  data->req.httpversion_sent = httpversion;
  buf = Fetch_dyn_ptr(req);
  blen = Fetch_dyn_len(req);
  if (!Fetch_creader_total_length(data))
  {
    /* Request without body. Try to send directly from the buf given. */
    data->req.eos_read = TRUE;
    result = xfer_send(data, buf, blen, blen, &nwritten);
    if (result)
      return result;
    buf += nwritten;
    blen -= nwritten;
  }

  if (blen)
  {
    /* Either we have a request body, or we could not send the complete
     * request in one go. Buffer the remainder and try to add as much
     * body bytes as room is left in the buffer. Then flush. */
    result = req_send_buffer_add(data, buf, blen, blen);
    if (result)
      return result;

    return Fetch_req_send_more(data);
  }
  return FETCHE_OK;
}

bool Fetch_req_sendbuf_empty(struct Fetch_easy *data)
{
  return !data->req.sendbuf_init || Fetch_bufq_is_empty(&data->req.sendbuf);
}

bool Fetch_req_want_send(struct Fetch_easy *data)
{
  /* Not done and
   * - KEEP_SEND and not PAUSEd.
   * - or request has buffered data to send
   * - or transfer connection has pending data to send */
  return !data->req.done &&
         (((data->req.keepon & KEEP_SENDBITS) == KEEP_SEND) ||
          !Fetch_req_sendbuf_empty(data) ||
          Fetch_xfer_needs_flush(data));
}

bool Fetch_req_done_sending(struct Fetch_easy *data)
{
  return data->req.upload_done && !Fetch_req_want_send(data);
}

FETCHcode Fetch_req_send_more(struct Fetch_easy *data)
{
  FETCHcode result;

  /* Fill our send buffer if more from client can be read. */
  if (!data->req.upload_aborted &&
      !data->req.eos_read &&
      !(data->req.keepon & KEEP_SEND_PAUSE) &&
      !Fetch_bufq_is_full(&data->req.sendbuf))
  {
    ssize_t nread = Fetch_bufq_sipn(&data->req.sendbuf, 0,
                                   add_from_client, data, &result);
    if (nread < 0 && result != FETCHE_AGAIN)
      return result;
  }

  result = req_flush(data);
  if (result == FETCHE_AGAIN)
    result = FETCHE_OK;

  return result;
}

FETCHcode Fetch_req_abort_sending(struct Fetch_easy *data)
{
  if (!data->req.upload_done)
  {
    Fetch_bufq_reset(&data->req.sendbuf);
    data->req.upload_aborted = TRUE;
    /* no longer KEEP_SEND and KEEP_SEND_PAUSE */
    data->req.keepon &= ~KEEP_SENDBITS;
    return req_set_upload_done(data);
  }
  return FETCHE_OK;
}

FETCHcode Fetch_req_stop_send_recv(struct Fetch_easy *data)
{
  /* stop receiving and ALL sending as well, including PAUSE and HOLD.
   * We might still be paused on receive client writes though, so
   * keep those bits around. */
  data->req.keepon &= ~(KEEP_RECV | KEEP_SENDBITS);
  return Fetch_req_abort_sending(data);
}
