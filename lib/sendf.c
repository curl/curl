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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif

#include <curl/curl.h>

#include "urldata.h"
#include "sendf.h"
#include "cfilters.h"
#include "connect.h"
#include "content_encoding.h"
#include "cw-out.h"
#include "vtls/vtls.h"
#include "vssh/ssh.h"
#include "easyif.h"
#include "multiif.h"
#include "strerror.h"
#include "select.h"
#include "strdup.h"
#include "http2.h"
#include "progress.h"
#include "warnless.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static CURLcode do_init_writer_stack(struct Curl_easy *data);

/* Curl_client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.
 */
CURLcode Curl_client_write(struct Curl_easy *data,
                           int type, const char *buf, size_t blen)
{
  CURLcode result;

  /* it is one of those, at least */
  DEBUGASSERT(type & (CLIENTWRITE_BODY|CLIENTWRITE_HEADER|CLIENTWRITE_INFO));
  /* BODY is only BODY (with optional EOS) */
  DEBUGASSERT(!(type & CLIENTWRITE_BODY) ||
              ((type & ~(CLIENTWRITE_BODY|CLIENTWRITE_EOS)) == 0));
  /* INFO is only INFO (with optional EOS) */
  DEBUGASSERT(!(type & CLIENTWRITE_INFO) ||
              ((type & ~(CLIENTWRITE_INFO|CLIENTWRITE_EOS)) == 0));

  if(!data->req.writer_stack) {
    result = do_init_writer_stack(data);
    if(result)
      return result;
    DEBUGASSERT(data->req.writer_stack);
  }

  result = Curl_cwriter_write(data, data->req.writer_stack, type, buf, blen);
  CURL_TRC_WRITE(data, "client_write(type=%x, len=%zu) -> %d",
                 type, blen, result);
  return result;
}

static void cl_reset_writer(struct Curl_easy *data)
{
  struct Curl_cwriter *writer = data->req.writer_stack;
  while(writer) {
    data->req.writer_stack = writer->next;
    writer->cwt->do_close(data, writer);
    free(writer);
    writer = data->req.writer_stack;
  }
}

static void cl_reset_reader(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader_stack;
  while(reader) {
    data->req.reader_stack = reader->next;
    reader->crt->do_close(data, reader);
    free(reader);
    reader = data->req.reader_stack;
  }
}

void Curl_client_cleanup(struct Curl_easy *data)
{
  cl_reset_reader(data);
  cl_reset_writer(data);

  data->req.bytecount = 0;
  data->req.headerline = 0;
}

void Curl_client_reset(struct Curl_easy *data)
{
  if(data->req.rewind_read) {
    /* already requested */
    CURL_TRC_READ(data, "client_reset, will rewind reader");
  }
  else {
    CURL_TRC_READ(data, "client_reset, clear readers");
    cl_reset_reader(data);
  }
  cl_reset_writer(data);

  data->req.bytecount = 0;
  data->req.headerline = 0;
}

CURLcode Curl_client_start(struct Curl_easy *data)
{
  if(data->req.rewind_read) {
    struct Curl_creader *r = data->req.reader_stack;
    CURLcode result = CURLE_OK;

    CURL_TRC_READ(data, "client start, rewind readers");
    while(r) {
      result = r->crt->rewind(data, r);
      if(result) {
        failf(data, "rewind of client reader '%s' failed: %d",
              r->crt->name, result);
        return result;
      }
      r = r->next;
    }
    data->req.rewind_read = FALSE;
    cl_reset_reader(data);
  }
  return CURLE_OK;
}

bool Curl_creader_will_rewind(struct Curl_easy *data)
{
  return data->req.rewind_read;
}

void Curl_creader_set_rewind(struct Curl_easy *data, bool enable)
{
  data->req.rewind_read = !!enable;
}

/* Write data using an unencoding writer stack. */
CURLcode Curl_cwriter_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes)
{
  if(!writer)
    return CURLE_WRITE_ERROR;
  return writer->cwt->do_write(data, writer, type, buf, nbytes);
}

CURLcode Curl_cwriter_def_init(struct Curl_easy *data,
                               struct Curl_cwriter *writer)
{
  (void)data;
  (void)writer;
  return CURLE_OK;
}

CURLcode Curl_cwriter_def_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t nbytes)
{
  return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
}

void Curl_cwriter_def_close(struct Curl_easy *data,
                            struct Curl_cwriter *writer)
{
  (void) data;
  (void) writer;
}

static size_t get_max_body_write_len(struct Curl_easy *data, curl_off_t limit)
{
  if(limit != -1) {
    /* How much more are we allowed to write? */
    curl_off_t remain_diff;
    remain_diff = limit - data->req.bytecount;
    if(remain_diff < 0) {
      /* already written too much! */
      return 0;
    }
#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T
    else if(remain_diff > SSIZE_T_MAX) {
      return SIZE_T_MAX;
    }
#endif
    else {
      return (size_t)remain_diff;
    }
  }
  return SIZE_T_MAX;
}

struct cw_download_ctx {
  struct Curl_cwriter super;
  BIT(started_response);
};
/* Download client writer in phase CURL_CW_PROTOCOL that
 * sees the "real" download body data. */
static CURLcode cw_download_write(struct Curl_easy *data,
                                  struct Curl_cwriter *writer, int type,
                                  const char *buf, size_t nbytes)
{
  struct cw_download_ctx *ctx = writer->ctx;
  CURLcode result;
  size_t nwrite, excess_len = 0;
  bool is_connect = !!(type & CLIENTWRITE_CONNECT);

  if(!is_connect && !ctx->started_response) {
    Curl_pgrsTime(data, TIMER_STARTTRANSFER);
    ctx->started_response = TRUE;
  }

  if(!(type & CLIENTWRITE_BODY)) {
    if(is_connect && data->set.suppress_connect_headers)
      return CURLE_OK;
    result = Curl_cwriter_write(data, writer->next, type, buf, nbytes);
    CURL_TRC_WRITE(data, "download_write header(type=%x, blen=%zu) -> %d",
                   type, nbytes, result);
    return result;
  }

  /* Here, we deal with REAL BODY bytes. All filtering and transfer
   * encodings have been applied and only the true content, e.g. BODY,
   * bytes are passed here.
   * This allows us to check sizes, update stats, etc. independent
   * from the protocol in play. */

  if(data->req.no_body && nbytes > 0) {
    /* BODY arrives although we want none, bail out */
    streamclose(data->conn, "ignoring body");
    CURL_TRC_WRITE(data, "download_write body(type=%x, blen=%zu), "
                   "did not want a BODY", type, nbytes);
    data->req.download_done = TRUE;
    if(data->info.header_size)
      /* if headers have been received, this is fine */
      return CURLE_OK;
    return CURLE_WEIRD_SERVER_REPLY;
  }

  /* Determine if we see any bytes in excess to what is allowed.
   * We write the allowed bytes and handle excess further below.
   * This gives deterministic BODY writes on varying buffer receive
   * lengths. */
  nwrite = nbytes;
  if(-1 != data->req.maxdownload) {
    size_t wmax = get_max_body_write_len(data, data->req.maxdownload);
    if(nwrite > wmax) {
      excess_len = nbytes - wmax;
      nwrite = wmax;
    }

    if(nwrite == wmax) {
      data->req.download_done = TRUE;
    }

    if((type & CLIENTWRITE_EOS) && !data->req.no_body &&
       (data->req.maxdownload > data->req.bytecount)) {
      failf(data, "end of response with %" FMT_OFF_T " bytes missing",
            data->req.maxdownload - data->req.bytecount);
      return CURLE_PARTIAL_FILE;
    }
  }

  /* Error on too large filesize is handled below, after writing
   * the permitted bytes */
  if(data->set.max_filesize && !data->req.ignorebody) {
    size_t wmax = get_max_body_write_len(data, data->set.max_filesize);
    if(nwrite > wmax) {
      nwrite = wmax;
    }
  }

  if(!data->req.ignorebody && (nwrite || (type & CLIENTWRITE_EOS))) {
    result = Curl_cwriter_write(data, writer->next, type, buf, nwrite);
    CURL_TRC_WRITE(data, "download_write body(type=%x, blen=%zu) -> %d",
                   type, nbytes, result);
    if(result)
      return result;
  }
  /* Update stats, write and report progress */
  data->req.bytecount += nwrite;
  result = Curl_pgrsSetDownloadCounter(data, data->req.bytecount);
  if(result)
    return result;

  if(excess_len) {
    if(!data->req.ignorebody) {
      infof(data,
            "Excess found writing body:"
            " excess = %zu"
            ", size = %" FMT_OFF_T
            ", maxdownload = %" FMT_OFF_T
            ", bytecount = %" FMT_OFF_T,
            excess_len, data->req.size, data->req.maxdownload,
            data->req.bytecount);
      connclose(data->conn, "excess found in a read");
    }
  }
  else if((nwrite < nbytes) && !data->req.ignorebody) {
    failf(data, "Exceeded the maximum allowed file size "
          "(%" FMT_OFF_T ") with %" FMT_OFF_T " bytes",
          data->set.max_filesize, data->req.bytecount);
    return CURLE_FILESIZE_EXCEEDED;
  }

  return CURLE_OK;
}

static const struct Curl_cwtype cw_download = {
  "protocol",
  NULL,
  Curl_cwriter_def_init,
  cw_download_write,
  Curl_cwriter_def_close,
  sizeof(struct cw_download_ctx)
};

/* RAW client writer in phase CURL_CW_RAW that
 * enabled tracing of raw data. */
static CURLcode cw_raw_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes)
{
  if(type & CLIENTWRITE_BODY && data->set.verbose && !data->req.ignorebody) {
    Curl_debug(data, CURLINFO_DATA_IN, (char *)buf, nbytes);
  }
  return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
}

static const struct Curl_cwtype cw_raw = {
  "raw",
  NULL,
  Curl_cwriter_def_init,
  cw_raw_write,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

/* Create an unencoding writer stage using the given handler. */
CURLcode Curl_cwriter_create(struct Curl_cwriter **pwriter,
                                   struct Curl_easy *data,
                                   const struct Curl_cwtype *cwt,
                                   Curl_cwriter_phase phase)
{
  struct Curl_cwriter *writer = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  void *p;

  DEBUGASSERT(cwt->cwriter_size >= sizeof(struct Curl_cwriter));
  p = calloc(1, cwt->cwriter_size);
  if(!p)
    goto out;

  writer = (struct Curl_cwriter *)p;
  writer->cwt = cwt;
  writer->ctx = p;
  writer->phase = phase;
  result = cwt->do_init(data, writer);

out:
  *pwriter = result ? NULL : writer;
  if(result)
    free(writer);
  return result;
}

void Curl_cwriter_free(struct Curl_easy *data,
                             struct Curl_cwriter *writer)
{
  if(writer) {
    writer->cwt->do_close(data, writer);
    free(writer);
  }
}

size_t Curl_cwriter_count(struct Curl_easy *data, Curl_cwriter_phase phase)
{
  struct Curl_cwriter *w;
  size_t n = 0;

  for(w = data->req.writer_stack; w; w = w->next) {
    if(w->phase == phase)
      ++n;
  }
  return n;
}

static CURLcode do_init_writer_stack(struct Curl_easy *data)
{
  struct Curl_cwriter *writer;
  CURLcode result;

  DEBUGASSERT(!data->req.writer_stack);
  result = Curl_cwriter_create(&data->req.writer_stack,
                               data, &Curl_cwt_out, CURL_CW_CLIENT);
  if(result)
    return result;

  result = Curl_cwriter_create(&writer, data, &cw_download, CURL_CW_PROTOCOL);
  if(result)
    return result;
  result = Curl_cwriter_add(data, writer);
  if(result) {
    Curl_cwriter_free(data, writer);
  }

  result = Curl_cwriter_create(&writer, data, &cw_raw, CURL_CW_RAW);
  if(result)
    return result;
  result = Curl_cwriter_add(data, writer);
  if(result) {
    Curl_cwriter_free(data, writer);
  }
  return result;
}

CURLcode Curl_cwriter_add(struct Curl_easy *data,
                          struct Curl_cwriter *writer)
{
  CURLcode result;
  struct Curl_cwriter **anchor = &data->req.writer_stack;

  if(!*anchor) {
    result = do_init_writer_stack(data);
    if(result)
      return result;
  }

  /* Insert the writer as first in its phase.
   * Skip existing writers of lower phases. */
  while(*anchor && (*anchor)->phase < writer->phase)
    anchor = &((*anchor)->next);
  writer->next = *anchor;
  *anchor = writer;
  return CURLE_OK;
}

struct Curl_cwriter *Curl_cwriter_get_by_name(struct Curl_easy *data,
                                              const char *name)
{
  struct Curl_cwriter *writer;
  for(writer = data->req.writer_stack; writer; writer = writer->next) {
    if(!strcmp(name, writer->cwt->name))
      return writer;
  }
  return NULL;
}

struct Curl_cwriter *Curl_cwriter_get_by_type(struct Curl_easy *data,
                                              const struct Curl_cwtype *cwt)
{
  struct Curl_cwriter *writer;
  for(writer = data->req.writer_stack; writer; writer = writer->next) {
    if(writer->cwt == cwt)
      return writer;
  }
  return NULL;
}

bool Curl_cwriter_is_paused(struct Curl_easy *data)
{
  return Curl_cw_out_is_paused(data);
}

CURLcode Curl_cwriter_unpause(struct Curl_easy *data)
{
  return Curl_cw_out_unpause(data);
}

CURLcode Curl_creader_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen, size_t *nread, bool *eos)
{
  *nread = 0;
  *eos = FALSE;
  if(!reader)
    return CURLE_READ_ERROR;
  return reader->crt->do_read(data, reader, buf, blen, nread, eos);
}

CURLcode Curl_creader_def_init(struct Curl_easy *data,
                               struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

void Curl_creader_def_close(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
}

CURLcode Curl_creader_def_read(struct Curl_easy *data,
                               struct Curl_creader *reader,
                               char *buf, size_t blen,
                               size_t *nread, bool *eos)
{
  if(reader->next)
    return reader->next->crt->do_read(data, reader->next, buf, blen,
                                      nread, eos);
  else {
    *nread = 0;
    *eos = FALSE;
    return CURLE_READ_ERROR;
  }
}

bool Curl_creader_def_needs_rewind(struct Curl_easy *data,
                                   struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return FALSE;
}

curl_off_t Curl_creader_def_total_length(struct Curl_easy *data,
                                         struct Curl_creader *reader)
{
  return reader->next ?
         reader->next->crt->total_length(data, reader->next) : -1;
}

CURLcode Curl_creader_def_resume_from(struct Curl_easy *data,
                                      struct Curl_creader *reader,
                                      curl_off_t offset)
{
  (void)data;
  (void)reader;
  (void)offset;
  return CURLE_READ_ERROR;
}

CURLcode Curl_creader_def_rewind(struct Curl_easy *data,
                                 struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

CURLcode Curl_creader_def_unpause(struct Curl_easy *data,
                                  struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

bool Curl_creader_def_is_paused(struct Curl_easy *data,
                                struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return FALSE;
}

void Curl_creader_def_done(struct Curl_easy *data,
                           struct Curl_creader *reader, int premature)
{
  (void)data;
  (void)reader;
  (void)premature;
}

struct cr_in_ctx {
  struct Curl_creader super;
  curl_read_callback read_cb;
  void *cb_user_data;
  curl_off_t total_len;
  curl_off_t read_len;
  CURLcode error_result;
  BIT(seen_eos);
  BIT(errored);
  BIT(has_used_cb);
  BIT(is_paused);
};

static CURLcode cr_in_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  ctx->read_cb = data->state.fread_func;
  ctx->cb_user_data = data->state.in;
  ctx->total_len = -1;
  ctx->read_len = 0;
  return CURLE_OK;
}

/* Real client reader to installed client callbacks. */
static CURLcode cr_in_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_in_ctx *ctx = reader->ctx;
  size_t nread;

  ctx->is_paused = FALSE;

  /* Once we have errored, we will return the same error forever */
  if(ctx->errored) {
    *pnread = 0;
    *peos = FALSE;
    return ctx->error_result;
  }
  if(ctx->seen_eos) {
    *pnread = 0;
    *peos = TRUE;
    return CURLE_OK;
  }
  /* respect length limitations */
  if(ctx->total_len >= 0) {
    curl_off_t remain = ctx->total_len - ctx->read_len;
    if(remain <= 0)
      blen = 0;
    else if(remain < (curl_off_t)blen)
      blen = (size_t)remain;
  }
  nread = 0;
  if(ctx->read_cb && blen) {
    Curl_set_in_callback(data, TRUE);
    nread = ctx->read_cb(buf, 1, blen, ctx->cb_user_data);
    Curl_set_in_callback(data, FALSE);
    ctx->has_used_cb = TRUE;
  }

  switch(nread) {
  case 0:
    if((ctx->total_len >= 0) && (ctx->read_len < ctx->total_len)) {
      failf(data, "client read function EOF fail, "
            "only %"FMT_OFF_T"/%"FMT_OFF_T " of needed bytes read",
            ctx->read_len, ctx->total_len);
      return CURLE_READ_ERROR;
    }
    *pnread = 0;
    *peos = TRUE;
    ctx->seen_eos = TRUE;
    break;

  case CURL_READFUNC_ABORT:
    failf(data, "operation aborted by callback");
    *pnread = 0;
    *peos = FALSE;
    ctx->errored = TRUE;
    ctx->error_result = CURLE_ABORTED_BY_CALLBACK;
    return CURLE_ABORTED_BY_CALLBACK;

  case CURL_READFUNC_PAUSE:
    if(data->conn->handler->flags & PROTOPT_NONETWORK) {
      /* protocols that work without network cannot be paused. This is
         actually only FILE:// just now, and it cannot pause since the transfer
         is not done using the "normal" procedure. */
      failf(data, "Read callback asked for PAUSE when not supported");
      return CURLE_READ_ERROR;
    }
    /* CURL_READFUNC_PAUSE pauses read callbacks that feed socket writes */
    CURL_TRC_READ(data, "cr_in_read, callback returned CURL_READFUNC_PAUSE");
    ctx->is_paused = TRUE;
    data->req.keepon |= KEEP_SEND_PAUSE; /* mark socket send as paused */
    *pnread = 0;
    *peos = FALSE;
    break; /* nothing was read */

  default:
    if(nread > blen) {
      /* the read function returned a too large value */
      failf(data, "read function returned funny value");
      *pnread = 0;
      *peos = FALSE;
      ctx->errored = TRUE;
      ctx->error_result = CURLE_READ_ERROR;
      return CURLE_READ_ERROR;
    }
    ctx->read_len += nread;
    if(ctx->total_len >= 0)
      ctx->seen_eos = (ctx->read_len >= ctx->total_len);
    *pnread = nread;
    *peos = ctx->seen_eos;
    break;
  }
  CURL_TRC_READ(data, "cr_in_read(len=%zu, total=%"FMT_OFF_T
                ", read=%"FMT_OFF_T") -> %d, nread=%zu, eos=%d",
                blen, ctx->total_len, ctx->read_len, CURLE_OK,
                *pnread, *peos);
  return CURLE_OK;
}

static bool cr_in_needs_rewind(struct Curl_easy *data,
                               struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->has_used_cb;
}

static curl_off_t cr_in_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->total_len;
}

static CURLcode cr_in_resume_from(struct Curl_easy *data,
                                  struct Curl_creader *reader,
                                  curl_off_t offset)
{
  struct cr_in_ctx *ctx = reader->ctx;
  int seekerr = CURL_SEEKFUNC_CANTSEEK;

  DEBUGASSERT(data->conn);
  /* already started reading? */
  if(ctx->read_len)
    return CURLE_READ_ERROR;

  if(data->set.seek_func) {
    Curl_set_in_callback(data, TRUE);
    seekerr = data->set.seek_func(data->set.seek_client, offset, SEEK_SET);
    Curl_set_in_callback(data, FALSE);
  }

  if(seekerr != CURL_SEEKFUNC_OK) {
    curl_off_t passed = 0;

    if(seekerr != CURL_SEEKFUNC_CANTSEEK) {
      failf(data, "Could not seek stream");
      return CURLE_READ_ERROR;
    }
    /* when seekerr == CURL_SEEKFUNC_CANTSEEK (cannot seek to offset) */
    do {
      char scratch[4*1024];
      size_t readthisamountnow =
        (offset - passed > (curl_off_t)sizeof(scratch)) ?
        sizeof(scratch) :
        curlx_sotouz(offset - passed);
      size_t actuallyread;

      Curl_set_in_callback(data, TRUE);
      actuallyread = ctx->read_cb(scratch, 1, readthisamountnow,
                                  ctx->cb_user_data);
      Curl_set_in_callback(data, FALSE);

      passed += actuallyread;
      if((actuallyread == 0) || (actuallyread > readthisamountnow)) {
        /* this checks for greater-than only to make sure that the
           CURL_READFUNC_ABORT return code still aborts */
        failf(data, "Could only read %" FMT_OFF_T " bytes from the input",
              passed);
        return CURLE_READ_ERROR;
      }
    } while(passed < offset);
  }

  /* now, decrease the size of the read */
  if(ctx->total_len > 0) {
    ctx->total_len -= offset;

    if(ctx->total_len <= 0) {
      failf(data, "File already completely uploaded");
      return CURLE_PARTIAL_FILE;
    }
  }
  /* we have passed, proceed as normal */
  return CURLE_OK;
}

static CURLcode cr_in_rewind(struct Curl_easy *data,
                             struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;

  /* If we never invoked the callback, there is noting to rewind */
  if(!ctx->has_used_cb)
    return CURLE_OK;

  if(data->set.seek_func) {
    int err;

    Curl_set_in_callback(data, TRUE);
    err = (data->set.seek_func)(data->set.seek_client, 0, SEEK_SET);
    Curl_set_in_callback(data, FALSE);
    CURL_TRC_READ(data, "cr_in, rewind via set.seek_func -> %d", err);
    if(err) {
      failf(data, "seek callback returned error %d", (int)err);
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  else if(data->set.ioctl_func) {
    curlioerr err;

    Curl_set_in_callback(data, TRUE);
    err = (data->set.ioctl_func)(data, CURLIOCMD_RESTARTREAD,
                                 data->set.ioctl_client);
    Curl_set_in_callback(data, FALSE);
    CURL_TRC_READ(data, "cr_in, rewind via set.ioctl_func -> %d", (int)err);
    if(err) {
      failf(data, "ioctl callback returned error %d", (int)err);
      return CURLE_SEND_FAIL_REWIND;
    }
  }
  else {
    /* If no CURLOPT_READFUNCTION is used, we know that we operate on a
       given FILE * stream and we can actually attempt to rewind that
       ourselves with fseek() */
    if(data->state.fread_func == (curl_read_callback)fread) {
      int err = fseek(data->state.in, 0, SEEK_SET);
      CURL_TRC_READ(data, "cr_in, rewind via fseek -> %d(%d)",
                    (int)err, (int)errno);
      if(-1 != err)
        /* successful rewind */
        return CURLE_OK;
    }

    /* no callback set or failure above, makes us fail at once */
    failf(data, "necessary data rewind was not possible");
    return CURLE_SEND_FAIL_REWIND;
  }
  return CURLE_OK;
}

static CURLcode cr_in_unpause(struct Curl_easy *data,
                              struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  ctx->is_paused = FALSE;
  return CURLE_OK;
}

static bool cr_in_is_paused(struct Curl_easy *data,
                            struct Curl_creader *reader)
{
  struct cr_in_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->is_paused;
}

static const struct Curl_crtype cr_in = {
  "cr-in",
  cr_in_init,
  cr_in_read,
  Curl_creader_def_close,
  cr_in_needs_rewind,
  cr_in_total_length,
  cr_in_resume_from,
  cr_in_rewind,
  cr_in_unpause,
  cr_in_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_in_ctx)
};

CURLcode Curl_creader_create(struct Curl_creader **preader,
                             struct Curl_easy *data,
                             const struct Curl_crtype *crt,
                             Curl_creader_phase phase)
{
  struct Curl_creader *reader = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  void *p;

  DEBUGASSERT(crt->creader_size >= sizeof(struct Curl_creader));
  p = calloc(1, crt->creader_size);
  if(!p)
    goto out;

  reader = (struct Curl_creader *)p;
  reader->crt = crt;
  reader->ctx = p;
  reader->phase = phase;
  result = crt->do_init(data, reader);

out:
  *preader = result ? NULL : reader;
  if(result)
    free(reader);
  return result;
}

void Curl_creader_free(struct Curl_easy *data, struct Curl_creader *reader)
{
  if(reader) {
    reader->crt->do_close(data, reader);
    free(reader);
  }
}

struct cr_lc_ctx {
  struct Curl_creader super;
  struct bufq buf;
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
  BIT(prev_cr);   /* the last byte was a CR */
};

static CURLcode cr_lc_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  (void)data;
  Curl_bufq_init2(&ctx->buf, (16 * 1024), 1, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

static void cr_lc_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  (void)data;
  Curl_bufq_free(&ctx->buf);
}

/* client reader doing line end conversions. */
static CURLcode cr_lc_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_lc_ctx *ctx = reader->ctx;
  CURLcode result;
  size_t nread, i, start, n;
  bool eos;

  if(ctx->eos) {
    *pnread = 0;
    *peos = TRUE;
    return CURLE_OK;
  }

  if(Curl_bufq_is_empty(&ctx->buf)) {
    if(ctx->read_eos) {
      ctx->eos = TRUE;
      *pnread = 0;
      *peos = TRUE;
      return CURLE_OK;
    }
    /* Still getting data form the next reader, ctx->buf is empty */
    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;
    ctx->read_eos = eos;

    if(!nread || !memchr(buf, '\n', nread)) {
      /* nothing to convert, return this right away */
      if(ctx->read_eos)
        ctx->eos = TRUE;
      *pnread = nread;
      *peos = ctx->eos;
      goto out;
    }

    /* at least one \n might need conversion to '\r\n', place into ctx->buf */
    for(i = start = 0; i < nread; ++i) {
      /* if this byte is not an LF character, or if the preceding character is
         a CR (meaning this already is a CRLF pair), go to next */
      if((buf[i] != '\n') || ctx->prev_cr) {
        ctx->prev_cr = (buf[i] == '\r');
        continue;
      }
      ctx->prev_cr = FALSE;
      /* on a soft limit bufq, we do not need to check length */
      result = Curl_bufq_cwrite(&ctx->buf, buf + start, i - start, &n);
      if(!result)
        result = Curl_bufq_cwrite(&ctx->buf, STRCONST("\r\n"), &n);
      if(result)
        return result;
      start = i + 1;
      if(!data->set.crlf && (data->state.infilesize != -1)) {
        /* we are here only because FTP is in ASCII mode...
           bump infilesize for the LF we just added */
        data->state.infilesize++;
        /* comment: this might work for FTP, but in HTTP we could not change
         * the content length after having started the request... */
      }
    }

    if(start < i) { /* leftover */
      result = Curl_bufq_cwrite(&ctx->buf, buf + start, i - start, &n);
      if(result)
        return result;
    }
  }

  DEBUGASSERT(!Curl_bufq_is_empty(&ctx->buf));
  *peos = FALSE;
  result = Curl_bufq_cread(&ctx->buf, buf, blen, pnread);
  if(!result && ctx->read_eos && Curl_bufq_is_empty(&ctx->buf)) {
    /* no more data, read all, done. */
    ctx->eos = TRUE;
    *peos = TRUE;
  }

out:
  CURL_TRC_READ(data, "cr_lc_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, result, *pnread, *peos);
  return result;
}

static curl_off_t cr_lc_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

static const struct Curl_crtype cr_lc = {
  "cr-lineconv",
  cr_lc_init,
  cr_lc_read,
  cr_lc_close,
  Curl_creader_def_needs_rewind,
  cr_lc_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_lc_ctx)
};

static CURLcode cr_lc_add(struct Curl_easy *data)
{
  struct Curl_creader *reader = NULL;
  CURLcode result;

  result = Curl_creader_create(&reader, data, &cr_lc,
                               CURL_CR_CONTENT_ENCODE);
  if(!result)
    result = Curl_creader_add(data, reader);

  if(result && reader)
    Curl_creader_free(data, reader);
  return result;
}

static CURLcode do_init_reader_stack(struct Curl_easy *data,
                                     struct Curl_creader *r)
{
  CURLcode result = CURLE_OK;
  curl_off_t clen;

  DEBUGASSERT(r);
  DEBUGASSERT(r->crt);
  DEBUGASSERT(r->phase == CURL_CR_CLIENT);
  DEBUGASSERT(!data->req.reader_stack);

  data->req.reader_stack = r;
  clen = r->crt->total_length(data, r);
  /* if we do not have 0 length init, and crlf conversion is wanted,
   * add the reader for it */
  if(clen && (data->set.crlf
#ifdef CURL_PREFER_LF_LINEENDS
     || data->state.prefer_ascii
#endif
    )) {
    result = cr_lc_add(data);
    if(result)
      return result;
  }

  return result;
}

CURLcode Curl_creader_set_fread(struct Curl_easy *data, curl_off_t len)
{
  CURLcode result;
  struct Curl_creader *r;
  struct cr_in_ctx *ctx;

  result = Curl_creader_create(&r, data, &cr_in, CURL_CR_CLIENT);
  if(result)
    goto out;
  ctx = r->ctx;
  ctx->total_len = len;

  cl_reset_reader(data);
  result = do_init_reader_stack(data, r);
out:
  CURL_TRC_READ(data, "add fread reader, len=%"FMT_OFF_T " -> %d",
                len, result);
  return result;
}

CURLcode Curl_creader_add(struct Curl_easy *data,
                          struct Curl_creader *reader)
{
  CURLcode result;
  struct Curl_creader **anchor = &data->req.reader_stack;

  if(!*anchor) {
    result = Curl_creader_set_fread(data, data->state.infilesize);
    if(result)
      return result;
  }

  /* Insert the writer as first in its phase.
   * Skip existing readers of lower phases. */
  while(*anchor && (*anchor)->phase < reader->phase)
    anchor = &((*anchor)->next);
  reader->next = *anchor;
  *anchor = reader;
  return CURLE_OK;
}

CURLcode Curl_creader_set(struct Curl_easy *data, struct Curl_creader *r)
{
  CURLcode result;

  DEBUGASSERT(r);
  DEBUGASSERT(r->crt);
  DEBUGASSERT(r->phase == CURL_CR_CLIENT);

  cl_reset_reader(data);
  result = do_init_reader_stack(data, r);
  if(result)
    Curl_creader_free(data, r);
  return result;
}

CURLcode Curl_client_read(struct Curl_easy *data, char *buf, size_t blen,
                          size_t *nread, bool *eos)
{
  CURLcode result;

  DEBUGASSERT(buf);
  DEBUGASSERT(blen);
  DEBUGASSERT(nread);
  DEBUGASSERT(eos);

  if(!data->req.reader_stack) {
    result = Curl_creader_set_fread(data, data->state.infilesize);
    if(result)
      return result;
    DEBUGASSERT(data->req.reader_stack);
  }

  result = Curl_creader_read(data, data->req.reader_stack, buf, blen,
                             nread, eos);
  CURL_TRC_READ(data, "client_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, result, *nread, *eos);
  return result;
}

bool Curl_creader_needs_rewind(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader_stack;
  while(reader) {
    if(reader->crt->needs_rewind(data, reader)) {
      CURL_TRC_READ(data, "client reader needs rewind before next request");
      return TRUE;
    }
    reader = reader->next;
  }
  return FALSE;
}

static CURLcode cr_null_read(struct Curl_easy *data,
                             struct Curl_creader *reader,
                             char *buf, size_t blen,
                             size_t *pnread, bool *peos)
{
  (void)data;
  (void)reader;
  (void)buf;
  (void)blen;
  *pnread = 0;
  *peos = TRUE;
  return CURLE_OK;
}

static curl_off_t cr_null_total_length(struct Curl_easy *data,
                                       struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return 0;
}

static const struct Curl_crtype cr_null = {
  "cr-null",
  Curl_creader_def_init,
  cr_null_read,
  Curl_creader_def_close,
  Curl_creader_def_needs_rewind,
  cr_null_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct Curl_creader)
};

CURLcode Curl_creader_set_null(struct Curl_easy *data)
{
  struct Curl_creader *r;
  CURLcode result;

  result = Curl_creader_create(&r, data, &cr_null, CURL_CR_CLIENT);
  if(result)
    return result;

  cl_reset_reader(data);
  return do_init_reader_stack(data, r);
}

struct cr_buf_ctx {
  struct Curl_creader super;
  const char *buf;
  size_t blen;
  size_t index;
};

static CURLcode cr_buf_read(struct Curl_easy *data,
                            struct Curl_creader *reader,
                            char *buf, size_t blen,
                            size_t *pnread, bool *peos)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  size_t nread = ctx->blen - ctx->index;

  (void)data;
  if(!nread || !ctx->buf) {
    *pnread = 0;
    *peos = TRUE;
  }
  else {
    if(nread > blen)
      nread = blen;
    memcpy(buf, ctx->buf + ctx->index, nread);
    *pnread = nread;
    ctx->index += nread;
    *peos = (ctx->index == ctx->blen);
  }
  CURL_TRC_READ(data, "cr_buf_read(len=%zu) -> 0, nread=%zu, eos=%d",
                blen, *pnread, *peos);
  return CURLE_OK;
}

static bool cr_buf_needs_rewind(struct Curl_easy *data,
                                struct Curl_creader *reader)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  (void)data;
  return ctx->index > 0;
}

static curl_off_t cr_buf_total_length(struct Curl_easy *data,
                                      struct Curl_creader *reader)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  (void)data;
  return (curl_off_t)ctx->blen;
}

static CURLcode cr_buf_resume_from(struct Curl_easy *data,
                                   struct Curl_creader *reader,
                                   curl_off_t offset)
{
  struct cr_buf_ctx *ctx = reader->ctx;
  size_t boffset;

  (void)data;
  DEBUGASSERT(data->conn);
  /* already started reading? */
  if(ctx->index)
    return CURLE_READ_ERROR;
  if(offset <= 0)
    return CURLE_OK;
  boffset = (size_t)offset;
  if(boffset > ctx->blen)
    return CURLE_READ_ERROR;

  ctx->buf += boffset;
  ctx->blen -= boffset;
  return CURLE_OK;
}

static const struct Curl_crtype cr_buf = {
  "cr-buf",
  Curl_creader_def_init,
  cr_buf_read,
  Curl_creader_def_close,
  cr_buf_needs_rewind,
  cr_buf_total_length,
  cr_buf_resume_from,
  Curl_creader_def_rewind,
  Curl_creader_def_unpause,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_buf_ctx)
};

CURLcode Curl_creader_set_buf(struct Curl_easy *data,
                               const char *buf, size_t blen)
{
  CURLcode result;
  struct Curl_creader *r;
  struct cr_buf_ctx *ctx;

  result = Curl_creader_create(&r, data, &cr_buf, CURL_CR_CLIENT);
  if(result)
    goto out;
  ctx = r->ctx;
  ctx->buf = buf;
  ctx->blen = blen;
  ctx->index = 0;

  cl_reset_reader(data);
  result = do_init_reader_stack(data, r);
out:
  CURL_TRC_READ(data, "add buf reader, len=%zu -> %d", blen, result);
  return result;
}

curl_off_t Curl_creader_total_length(struct Curl_easy *data)
{
  struct Curl_creader *r = data->req.reader_stack;
  return r ? r->crt->total_length(data, r) : -1;
}

curl_off_t Curl_creader_client_length(struct Curl_easy *data)
{
  struct Curl_creader *r = data->req.reader_stack;
  while(r && r->phase != CURL_CR_CLIENT)
    r = r->next;
  return r ? r->crt->total_length(data, r) : -1;
}

CURLcode Curl_creader_resume_from(struct Curl_easy *data, curl_off_t offset)
{
  struct Curl_creader *r = data->req.reader_stack;
  while(r && r->phase != CURL_CR_CLIENT)
    r = r->next;
  return r ? r->crt->resume_from(data, r, offset) : CURLE_READ_ERROR;
}

CURLcode Curl_creader_unpause(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader_stack;
  CURLcode result = CURLE_OK;

  while(reader) {
    result = reader->crt->unpause(data, reader);
    if(result)
      break;
    reader = reader->next;
  }
  return result;
}

bool Curl_creader_is_paused(struct Curl_easy *data)
{
  struct Curl_creader *reader = data->req.reader_stack;

  while(reader) {
    if(reader->crt->is_paused(data, reader))
      return TRUE;
    reader = reader->next;
  }
  return FALSE;
}

void Curl_creader_done(struct Curl_easy *data, int premature)
{
  struct Curl_creader *reader = data->req.reader_stack;
  while(reader) {
    reader->crt->done(data, reader, premature);
    reader = reader->next;
  }
}

struct Curl_creader *Curl_creader_get_by_type(struct Curl_easy *data,
                                              const struct Curl_crtype *crt)
{
  struct Curl_creader *r;
  for(r = data->req.reader_stack; r; r = r->next) {
    if(r->crt == crt)
      return r;
  }
  return NULL;

}
