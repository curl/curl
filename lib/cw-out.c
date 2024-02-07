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

#include <curl/curl.h>

#include "urldata.h"
#include "cfilters.h"
#include "headers.h"
#include "multiif.h"
#include "sendf.h"
#include "cw-out.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


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

/* Real client writer to installed callbacks. */
static CURLcode cw_out_write(struct Curl_easy *data,
                             struct Curl_cwriter *writer, int type,
                             const char *buf, size_t nbytes)
{
  (void)writer;
  if(!nbytes)
    return CURLE_OK;
  return chop_write(data, type, FALSE, (char *)buf, nbytes);
}

struct Curl_cwtype Curl_cwt_out = {
  "cw-out",
  NULL,
  Curl_cwriter_def_init,
  cw_out_write,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

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

