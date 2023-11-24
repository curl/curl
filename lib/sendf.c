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
#include "vtls/vtls.h"
#include "vssh/ssh.h"
#include "easyif.h"
#include "multiif.h"
#include "strerror.h"
#include "select.h"
#include "strdup.h"
#include "http2.h"
#include "headers.h"
#include "progress.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


static CURLcode do_init_stack(struct Curl_easy *data);

#if defined(CURL_DO_LINEEND_CONV) && !defined(CURL_DISABLE_FTP)
/*
 * convert_lineends() changes CRLF (\r\n) end-of-line markers to a single LF
 * (\n), with special processing for CRLF sequences that are split between two
 * blocks of data.  Remaining, bare CRs are changed to LFs.  The possibly new
 * size of the data is returned.
 */
static size_t convert_lineends(struct Curl_easy *data,
                               char *startPtr, size_t size)
{
  char *inPtr, *outPtr;

  /* sanity check */
  if(!startPtr || (size < 1)) {
    return size;
  }

  if(data->state.prev_block_had_trailing_cr) {
    /* The previous block of incoming data
       had a trailing CR, which was turned into a LF. */
    if(*startPtr == '\n') {
      /* This block of incoming data starts with the
         previous block's LF so get rid of it */
      memmove(startPtr, startPtr + 1, size-1);
      size--;
      /* and it wasn't a bare CR but a CRLF conversion instead */
      data->state.crlf_conversions++;
    }
    data->state.prev_block_had_trailing_cr = FALSE; /* reset the flag */
  }

  /* find 1st CR, if any */
  inPtr = outPtr = memchr(startPtr, '\r', size);
  if(inPtr) {
    /* at least one CR, now look for CRLF */
    while(inPtr < (startPtr + size-1)) {
      /* note that it's size-1, so we'll never look past the last byte */
      if(memcmp(inPtr, "\r\n", 2) == 0) {
        /* CRLF found, bump past the CR and copy the NL */
        inPtr++;
        *outPtr = *inPtr;
        /* keep track of how many CRLFs we converted */
        data->state.crlf_conversions++;
      }
      else {
        if(*inPtr == '\r') {
          /* lone CR, move LF instead */
          *outPtr = '\n';
        }
        else {
          /* not a CRLF nor a CR, just copy whatever it is */
          *outPtr = *inPtr;
        }
      }
      outPtr++;
      inPtr++;
    } /* end of while loop */

    if(inPtr < startPtr + size) {
      /* handle last byte */
      if(*inPtr == '\r') {
        /* deal with a CR at the end of the buffer */
        *outPtr = '\n'; /* copy a NL instead */
        /* note that a CRLF might be split across two blocks */
        data->state.prev_block_had_trailing_cr = TRUE;
      }
      else {
        /* copy last byte */
        *outPtr = *inPtr;
      }
      outPtr++;
    }
    if(outPtr < startPtr + size)
      /* tidy up by null terminating the now shorter data */
      *outPtr = '\0';

    return (outPtr - startPtr);
  }
  return size;
}
#endif /* CURL_DO_LINEEND_CONV && !CURL_DISABLE_FTP */

/*
 * Curl_nwrite() is an internal write function that sends data to the
 * server. Works with a socket index for the connection.
 *
 * If the write would block (CURLE_AGAIN), it returns CURLE_OK and
 * (*nwritten == 0). Otherwise we return regular CURLcode value.
 */
CURLcode Curl_nwrite(struct Curl_easy *data,
                     int sockindex,
                     const void *buf,
                     size_t blen,
                     ssize_t *pnwritten)
{
  ssize_t nwritten;
  CURLcode result = CURLE_OK;
  struct connectdata *conn;

  DEBUGASSERT(sockindex >= 0 && sockindex < 2);
  DEBUGASSERT(pnwritten);
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  conn = data->conn;
#ifdef CURLDEBUG
  {
    /* Allow debug builds to override this logic to force short sends
    */
    char *p = getenv("CURL_SMALLSENDS");
    if(p) {
      size_t altsize = (size_t)strtoul(p, NULL, 10);
      if(altsize)
        blen = CURLMIN(blen, altsize);
    }
  }
#endif
  nwritten = conn->send[sockindex](data, sockindex, buf, blen, &result);
  if(result == CURLE_AGAIN) {
    nwritten = 0;
    result = CURLE_OK;
  }
  else if(result) {
    nwritten = -1; /* make sure */
  }
  else {
    DEBUGASSERT(nwritten >= 0);
  }

  *pnwritten = nwritten;
  return result;
}

/*
 * Curl_write() is an internal write function that sends data to the
 * server. Works with plain sockets, SCP, SSL or kerberos.
 *
 * If the write would block (CURLE_AGAIN), we return CURLE_OK and
 * (*written == 0). Otherwise we return regular CURLcode value.
 */
CURLcode Curl_write(struct Curl_easy *data,
                    curl_socket_t sockfd,
                    const void *mem,
                    size_t len,
                    ssize_t *written)
{
  struct connectdata *conn;
  int num;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  conn = data->conn;
  num = (sockfd != CURL_SOCKET_BAD && sockfd == conn->sock[SECONDARYSOCKET]);
  return Curl_nwrite(data, num, mem, len, written);
}

static CURLcode pausewrite(struct Curl_easy *data,
                           int type, /* what type of data */
                           bool paused_body,
                           const char *ptr,
                           size_t len)
{
  /* signalled to pause sending on this connection, but since we have data
     we want to send we need to dup it to save a copy for when the sending
     is again enabled */
  struct SingleRequest *k = &data->req;
  struct UrlState *s = &data->state;
  unsigned int i;
  bool newtype = TRUE;

  Curl_conn_ev_data_pause(data, TRUE);

  if(s->tempcount) {
    for(i = 0; i< s->tempcount; i++) {
      if(s->tempwrite[i].type == type &&
         !!s->tempwrite[i].paused_body == !!paused_body) {
        /* data for this type exists */
        newtype = FALSE;
        break;
      }
    }
    DEBUGASSERT(i < 3);
    if(i >= 3)
      /* There are more types to store than what fits: very bad */
      return CURLE_OUT_OF_MEMORY;
  }
  else
    i = 0;

  if(newtype) {
    /* store this information in the state struct for later use */
    Curl_dyn_init(&s->tempwrite[i].b, DYN_PAUSE_BUFFER);
    s->tempwrite[i].type = type;
    s->tempwrite[i].paused_body = paused_body;
    s->tempcount++;
  }

  if(Curl_dyn_addn(&s->tempwrite[i].b, (unsigned char *)ptr, len))
    return CURLE_OUT_OF_MEMORY;

  /* mark the connection as RECV paused */
  k->keepon |= KEEP_RECV_PAUSE;

  return CURLE_OK;
}


/* chop_write() writes chunks of data not larger than CURL_MAX_WRITE_SIZE via
 * client write callback(s) and takes care of pause requests from the
 * callbacks.
 */
static CURLcode chop_write(struct Curl_easy *data,
                           int type,
                           bool skip_body_write,
                           char *optr,
                           size_t olen)
{
  struct connectdata *conn = data->conn;
  curl_write_callback writeheader = NULL;
  curl_write_callback writebody = NULL;
  char *ptr = optr;
  size_t len = olen;
  void *writebody_ptr = data->set.out;

  if(!len)
    return CURLE_OK;

  /* If reading is paused, append this data to the already held data for this
     type. */
  if(data->req.keepon & KEEP_RECV_PAUSE)
    return pausewrite(data, type, !skip_body_write, ptr, len);

  /* Determine the callback(s) to use. */
  if(!skip_body_write &&
     ((type & CLIENTWRITE_BODY) ||
      ((type & CLIENTWRITE_HEADER) && data->set.include_header))) {
#ifdef USE_WEBSOCKETS
    if(conn->handler->protocol & (CURLPROTO_WS|CURLPROTO_WSS)) {
      writebody = Curl_ws_writecb;
      writebody_ptr = data;
    }
    else
#endif
    writebody = data->set.fwrite_func;
  }
  if((type & (CLIENTWRITE_HEADER|CLIENTWRITE_INFO)) &&
     (data->set.fwrite_header || data->set.writeheader)) {
    /*
     * Write headers to the same callback or to the especially setup
     * header callback function (added after version 7.7.1).
     */
    writeheader =
      data->set.fwrite_header? data->set.fwrite_header: data->set.fwrite_func;
  }

  /* Chop data, write chunks. */
  while(len) {
    size_t chunklen = len <= CURL_MAX_WRITE_SIZE? len: CURL_MAX_WRITE_SIZE;

    if(writebody) {
      size_t wrote;
      Curl_set_in_callback(data, true);
      wrote = writebody(ptr, 1, chunklen, writebody_ptr);
      Curl_set_in_callback(data, false);

      if(CURL_WRITEFUNC_PAUSE == wrote) {
        if(conn->handler->flags & PROTOPT_NONETWORK) {
          /* Protocols that work without network cannot be paused. This is
             actually only FILE:// just now, and it can't pause since the
             transfer isn't done using the "normal" procedure. */
          failf(data, "Write callback asked for PAUSE when not supported");
          return CURLE_WRITE_ERROR;
        }
        return pausewrite(data, type, TRUE, ptr, len);
      }
      if(wrote != chunklen) {
        failf(data, "Failure writing output to destination");
        return CURLE_WRITE_ERROR;
      }
    }

    ptr += chunklen;
    len -= chunklen;
  }

#ifndef CURL_DISABLE_HTTP
  /* HTTP header, but not status-line */
  if((conn->handler->protocol & PROTO_FAMILY_HTTP) &&
     (type & CLIENTWRITE_HEADER) && !(type & CLIENTWRITE_STATUS) ) {
    unsigned char htype = (unsigned char)
      (type & CLIENTWRITE_CONNECT ? CURLH_CONNECT :
       (type & CLIENTWRITE_1XX ? CURLH_1XX :
        (type & CLIENTWRITE_TRAILER ? CURLH_TRAILER :
         CURLH_HEADER)));
    CURLcode result = Curl_headers_push(data, optr, htype);
    if(result)
      return result;
  }
#endif

  if(writeheader) {
    size_t wrote;

    Curl_set_in_callback(data, true);
    wrote = writeheader(optr, 1, olen, data->set.writeheader);
    Curl_set_in_callback(data, false);

    if(CURL_WRITEFUNC_PAUSE == wrote)
      return pausewrite(data, type, FALSE, optr, olen);
    if(wrote != olen) {
      failf(data, "Failed writing header");
      return CURLE_WRITE_ERROR;
    }
  }

  return CURLE_OK;
}


/* Curl_client_write() sends data to the write callback(s)

   The bit pattern defines to what "streams" to write to. Body and/or header.
   The defines are in sendf.h of course.

   If CURL_DO_LINEEND_CONV is enabled, data is converted IN PLACE to the
   local character encoding.  This is a problem and should be changed in
   the future to leave the original data alone.
 */
CURLcode Curl_client_write(struct Curl_easy *data,
                           int type, char *buf, size_t blen)
{
  CURLcode result;

#if !defined(CURL_DISABLE_FTP) && defined(CURL_DO_LINEEND_CONV)
  /* FTP data may need conversion. */
  if((type & CLIENTWRITE_BODY) &&
     (data->conn->handler->protocol & PROTO_FAMILY_FTP) &&
     data->conn->proto.ftpc.transfertype == 'A') {
    /* convert end-of-line markers */
    blen = convert_lineends(data, buf, blen);
  }
#endif
  /* it is one of those, at least */
  DEBUGASSERT(type & (CLIENTWRITE_BODY|CLIENTWRITE_HEADER|CLIENTWRITE_INFO));
  /* BODY is only BODY */
  DEBUGASSERT(!(type & CLIENTWRITE_BODY) || (type == CLIENTWRITE_BODY));
  /* INFO is only INFO */
  DEBUGASSERT(!(type & CLIENTWRITE_INFO) || (type == CLIENTWRITE_INFO));

  if(!data->req.writer_stack) {
    result = do_init_stack(data);
    if(result)
      return result;
    DEBUGASSERT(data->req.writer_stack);
  }

  return Curl_cwriter_write(data, data->req.writer_stack, type, buf, blen);
}

CURLcode Curl_client_unpause(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;

  if(data->state.tempcount) {
    /* there are buffers for sending that can be delivered as the receive
       pausing is lifted! */
    unsigned int i;
    unsigned int count = data->state.tempcount;
    struct tempbuf writebuf[3]; /* there can only be three */

    /* copy the structs to allow for immediate re-pausing */
    for(i = 0; i < data->state.tempcount; i++) {
      writebuf[i] = data->state.tempwrite[i];
      Curl_dyn_init(&data->state.tempwrite[i].b, DYN_PAUSE_BUFFER);
    }
    data->state.tempcount = 0;

    for(i = 0; i < count; i++) {
      /* even if one function returns error, this loops through and frees
         all buffers */
      if(!result)
        result = chop_write(data, writebuf[i].type,
                            !writebuf[i].paused_body,
                            Curl_dyn_ptr(&writebuf[i].b),
                            Curl_dyn_len(&writebuf[i].b));
      Curl_dyn_free(&writebuf[i].b);
    }
  }
  return result;
}

void Curl_client_cleanup(struct Curl_easy *data)
{
  struct Curl_cwriter *writer = data->req.writer_stack;
  size_t i;

  while(writer) {
    data->req.writer_stack = writer->next;
    writer->cwt->do_close(data, writer);
    free(writer);
    writer = data->req.writer_stack;
  }

  for(i = 0; i < data->state.tempcount; i++) {
    Curl_dyn_free(&data->state.tempwrite[i].b);
  }
  data->state.tempcount = 0;
  data->req.bytecount = 0;
  data->req.headerline = 0;
}

/* Write data using an unencoding writer stack. "nbytes" is not
   allowed to be 0. */
CURLcode Curl_cwriter_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes)
{
  if(!nbytes)
    return CURLE_OK;
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

/* Real client writer to installed callbacks. */
static CURLcode cw_client_write(struct Curl_easy *data,
                                struct Curl_cwriter *writer, int type,
                                const char *buf, size_t nbytes)
{
  (void)writer;
  if(!nbytes)
    return CURLE_OK;
  return chop_write(data, type, FALSE, (char *)buf, nbytes);
}

static const struct Curl_cwtype cw_client = {
  "client",
  NULL,
  Curl_cwriter_def_init,
  cw_client_write,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

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

/* Download client writer in phase CURL_CW_PROTOCOL that
 * sees the "real" download body data. */
static CURLcode cw_download_write(struct Curl_easy *data,
                                  struct Curl_cwriter *writer, int type,
                                  const char *buf, size_t nbytes)
{
  CURLcode result;
  size_t nwrite, excess_len = 0;
  const char *excess_data = NULL;

  if(!(type & CLIENTWRITE_BODY)) {
    if((type & CLIENTWRITE_CONNECT) && data->set.suppress_connect_headers)
      return CURLE_OK;
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
  }

  nwrite = nbytes;
  if(-1 != data->req.maxdownload) {
    size_t wmax = get_max_body_write_len(data, data->req.maxdownload);
    if(nwrite > wmax) {
      excess_len = nbytes - wmax;
      nwrite = wmax;
      excess_data = buf + nwrite;
    }

    if(nwrite == wmax) {
      data->req.download_done = TRUE;
    }
  }

  if(data->set.max_filesize) {
    size_t wmax = get_max_body_write_len(data, data->set.max_filesize);
    if(nwrite > wmax) {
      nwrite = wmax;
    }
  }

  data->req.bytecount += nwrite;
  ++data->req.bodywrites;
  if(!data->req.ignorebody && nwrite) {
    result = Curl_cwriter_write(data, writer->next, type, buf, nwrite);
    if(result)
      return result;
  }
  result = Curl_pgrsSetDownloadCounter(data, data->req.bytecount);
  if(result)
    return result;

  if(excess_len) {
    if(data->conn->handler->readwrite) {
      /* RTSP hack moved from transfer loop to here */
      bool readmore = FALSE; /* indicates data is incomplete, need more */
      size_t consumed = 0;
      result = data->conn->handler->readwrite(data, data->conn,
                                              excess_data, excess_len,
                                              &consumed, &readmore);
      if(result)
        return result;
      DEBUGASSERT(consumed <= excess_len);
      excess_len -= consumed;
      if(readmore) {
        data->req.download_done = FALSE;
        data->req.keepon |= KEEP_RECV; /* we're not done reading */
      }
    }
    if(excess_len && !data->req.ignorebody) {
      infof(data,
            "Excess found writing body:"
            " excess = %zu"
            ", size = %" CURL_FORMAT_CURL_OFF_T
            ", maxdownload = %" CURL_FORMAT_CURL_OFF_T
            ", bytecount = %" CURL_FORMAT_CURL_OFF_T,
            excess_len, data->req.size, data->req.maxdownload,
            data->req.bytecount);
      connclose(data->conn, "excess found in a read");
    }
  }
  else if(nwrite < nbytes) {
    failf(data, "Exceeded the maximum allowed file size "
          "(%" CURL_FORMAT_CURL_OFF_T ") with %"
          CURL_FORMAT_CURL_OFF_T " bytes",
          data->set.max_filesize, data->req.bytecount);
    return CURLE_FILESIZE_EXCEEDED;
  }

  return CURLE_OK;
}

static const struct Curl_cwtype cw_download = {
  "download",
  NULL,
  Curl_cwriter_def_init,
  cw_download_write,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
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
  struct Curl_cwriter *writer;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(cwt->cwriter_size >= sizeof(struct Curl_cwriter));
  writer = (struct Curl_cwriter *) calloc(1, cwt->cwriter_size);
  if(!writer)
    goto out;

  writer->cwt = cwt;
  writer->phase = phase;
  result = cwt->do_init(data, writer);

out:
  *pwriter = result? NULL : writer;
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

static CURLcode do_init_stack(struct Curl_easy *data)
{
  struct Curl_cwriter *writer;
  CURLcode result;

  DEBUGASSERT(!data->req.writer_stack);
  result = Curl_cwriter_create(&data->req.writer_stack,
                               data, &cw_client, CURL_CW_CLIENT);
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
    result = do_init_stack(data);
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


/*
 * Internal read-from-socket function. This is meant to deal with plain
 * sockets, SSL sockets and kerberos sockets.
 *
 * Returns a regular CURLcode value.
 */
CURLcode Curl_read(struct Curl_easy *data,   /* transfer */
                   curl_socket_t sockfd,     /* read from this socket */
                   char *buf,                /* store read data here */
                   size_t sizerequested,     /* max amount to read */
                   ssize_t *n)               /* amount bytes read */
{
  CURLcode result = CURLE_RECV_ERROR;
  ssize_t nread = 0;
  size_t bytesfromsocket = 0;
  char *buffertofill = NULL;
  struct connectdata *conn = data->conn;

  /* Set 'num' to 0 or 1, depending on which socket that has been sent here.
     If it is the second socket, we set num to 1. Otherwise to 0. This lets
     us use the correct ssl handle. */
  int num = (sockfd == conn->sock[SECONDARYSOCKET]);

  *n = 0; /* reset amount to zero */

  bytesfromsocket = CURLMIN(sizerequested, (size_t)data->set.buffer_size);
  buffertofill = buf;

  nread = conn->recv[num](data, num, buffertofill, bytesfromsocket, &result);
  if(nread < 0)
    goto out;

  *n += nread;
  result = CURLE_OK;
out:
  return result;
}
