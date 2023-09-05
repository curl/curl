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
#include "vtls/vtls.h"
#include "vssh/ssh.h"
#include "easyif.h"
#include "multiif.h"
#include "strerror.h"
#include "select.h"
#include "strdup.h"
#include "http2.h"
#include "headers.h"
#include "ws.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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
      if(s->tempwrite[i].type == type) {
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
    return pausewrite(data, type, ptr, len);

  /* Determine the callback(s) to use. */
  if(type & CLIENTWRITE_BODY) {
#ifdef USE_WEBSOCKETS
    if(conn->handler->protocol & (CURLPROTO_WS|CURLPROTO_WSS)) {
      writebody = Curl_ws_writecb;
      writebody_ptr = data;
    }
    else
#endif
    writebody = data->set.fwrite_func;
  }
  if((type & CLIENTWRITE_HEADER) &&
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
        return pausewrite(data, type, ptr, len);
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
      /* here we pass in the HEADER bit only since if this was body as well
         then it was passed already and clearly that didn't trigger the
         pause, so this is saved for later with the HEADER bit only */
      return pausewrite(data, CLIENTWRITE_HEADER |
                        (type & (CLIENTWRITE_STATUS|CLIENTWRITE_CONNECT|
                                 CLIENTWRITE_1XX|CLIENTWRITE_TRAILER)),
                        optr, olen);
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
                           int type,
                           char *ptr,
                           size_t len)
{
#if !defined(CURL_DISABLE_FTP) && defined(CURL_DO_LINEEND_CONV)
  /* FTP data may need conversion. */
  if((type & CLIENTWRITE_BODY) &&
     (data->conn->handler->protocol & PROTO_FAMILY_FTP) &&
     data->conn->proto.ftpc.transfertype == 'A') {
    /* convert end-of-line markers */
    len = convert_lineends(data, ptr, len);
  }
#endif
  return chop_write(data, type, ptr, len);
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
