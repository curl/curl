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
#ifndef UNDER_CE
#include <signal.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifndef HAVE_SOCKET
#error "We cannot compile without socket() support!"
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "netrc.h"

#include "content_encoding.h"
#include "hostip.h"
#include "cfilters.h"
#include "cw-out.h"
#include "transfer.h"
#include "sendf.h"
#include "speedcheck.h"
#include "progress.h"
#include "http.h"
#include "url.h"
#include "getinfo.h"
#include "vtls/vtls.h"
#include "vquic/vquic.h"
#include "select.h"
#include "multiif.h"
#include "connect.h"
#include "http2.h"
#include "mime.h"
#include "strcase.h"
#include "hsts.h"
#include "setopt.h"
#include "headers.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_SMTP) || \
    !defined(CURL_DISABLE_IMAP)
/*
 * checkheaders() checks the linked list of custom headers for a
 * particular header (prefix). Provide the prefix without colon!
 *
 * Returns a pointer to the first matching header or NULL if none matched.
 */
char *Curl_checkheaders(const struct Curl_easy *data,
                        const char *thisheader,
                        const size_t thislen)
{
  struct curl_slist *head;
  DEBUGASSERT(thislen);
  DEBUGASSERT(thisheader[thislen-1] != ':');

  for(head = data->set.headers; head; head = head->next) {
    if(strncasecompare(head->data, thisheader, thislen) &&
       Curl_headersep(head->data[thislen]) )
      return head->data;
  }

  return NULL;
}
#endif

static int data_pending(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;

  if(conn->handler->protocol&PROTO_FAMILY_FTP)
    return Curl_conn_data_pending(data, SECONDARYSOCKET);

  /* in the case of libssh2, we can never be really sure that we have emptied
     its internal buffers so we MUST always try until we get EAGAIN back */
  return conn->handler->protocol&(CURLPROTO_SCP|CURLPROTO_SFTP) ||
    Curl_conn_data_pending(data, FIRSTSOCKET);
}

/*
 * Check to see if CURLOPT_TIMECONDITION was met by comparing the time of the
 * remote document with the time provided by CURLOPT_TIMEVAL
 */
bool Curl_meets_timecondition(struct Curl_easy *data, time_t timeofdoc)
{
  if((timeofdoc == 0) || (data->set.timevalue == 0))
    return TRUE;

  switch(data->set.timecondition) {
  case CURL_TIMECOND_IFMODSINCE:
  default:
    if(timeofdoc <= data->set.timevalue) {
      infof(data,
            "The requested document is not new enough");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  case CURL_TIMECOND_IFUNMODSINCE:
    if(timeofdoc >= data->set.timevalue) {
      infof(data,
            "The requested document is not old enough");
      data->info.timecond = TRUE;
      return FALSE;
    }
    break;
  }

  return TRUE;
}

static CURLcode xfer_recv_shutdown(struct Curl_easy *data, bool *done)
{
  int sockindex;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  if(data->conn->sockfd == CURL_SOCKET_BAD)
    return CURLE_FAILED_INIT;
  sockindex = (data->conn->sockfd == data->conn->sock[SECONDARYSOCKET]);
  return Curl_conn_shutdown(data, sockindex, done);
}

static bool xfer_recv_shutdown_started(struct Curl_easy *data)
{
  int sockindex;

  if(!data || !data->conn)
    return FALSE;
  if(data->conn->sockfd == CURL_SOCKET_BAD)
    return FALSE;
  sockindex = (data->conn->sockfd == data->conn->sock[SECONDARYSOCKET]);
  return Curl_shutdown_started(data, sockindex);
}

CURLcode Curl_xfer_send_shutdown(struct Curl_easy *data, bool *done)
{
  int sockindex;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  if(data->conn->writesockfd == CURL_SOCKET_BAD)
    return CURLE_FAILED_INIT;
  sockindex = (data->conn->writesockfd == data->conn->sock[SECONDARYSOCKET]);
  return Curl_conn_shutdown(data, sockindex, done);
}

/**
 * Receive raw response data for the transfer.
 * @param data         the transfer
 * @param buf          buffer to keep response data received
 * @param blen         length of `buf`
 * @param eos_reliable if EOS detection in underlying connection is reliable
 * @param err error    code in case of -1 return
 * @return number of bytes read or -1 for error
 */
static ssize_t xfer_recv_resp(struct Curl_easy *data,
                              char *buf, size_t blen,
                              bool eos_reliable,
                              CURLcode *err)
{
  ssize_t nread;

  DEBUGASSERT(blen > 0);
  /* If we are reading BODY data and the connection does NOT handle EOF
   * and we know the size of the BODY data, limit the read amount */
  if(!eos_reliable && !data->req.header && data->req.size != -1) {
    curl_off_t totalleft = data->req.size - data->req.bytecount;
    if(totalleft <= 0)
      blen = 0;
    else if(totalleft < (curl_off_t)blen)
      blen = (size_t)totalleft;
  }
  else if(xfer_recv_shutdown_started(data)) {
    /* we already received everything. Do not try more. */
    blen = 0;
  }

  if(!blen) {
    /* want nothing more */
    *err = CURLE_OK;
    nread = 0;
  }
  else {
    *err = Curl_xfer_recv(data, buf, blen, &nread);
  }

  if(*err)
    return -1;
  if(nread == 0) {
    if(data->req.shutdown) {
      bool done;
      *err = xfer_recv_shutdown(data, &done);
      if(*err)
        return -1;
      if(!done) {
        *err = CURLE_AGAIN;
        return -1;
      }
    }
    DEBUGF(infof(data, "sendrecv_dl: we are done"));
  }
  DEBUGASSERT(nread >= 0);
  return nread;
}

/*
 * Go ahead and do a read if we have a readable socket or if
 * the stream was rewound (in which case we have data in a
 * buffer)
 */
static CURLcode sendrecv_dl(struct Curl_easy *data,
                            struct SingleRequest *k,
                            int *didwhat)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  char *buf, *xfer_buf;
  size_t blen, xfer_blen;
  int maxloops = 10;
  curl_off_t total_received = 0;
  bool is_multiplex = FALSE;

  result = Curl_multi_xfer_buf_borrow(data, &xfer_buf, &xfer_blen);
  if(result)
    goto out;

  /* This is where we loop until we have read everything there is to
     read or we get a CURLE_AGAIN */
  do {
    bool is_eos = FALSE;
    size_t bytestoread;
    ssize_t nread;

    if(!is_multiplex) {
      /* Multiplexed connection have inherent handling of EOF and we do not
       * have to carefully restrict the amount we try to read.
       * Multiplexed changes only in one direction. */
      is_multiplex = Curl_conn_is_multiplex(conn, FIRSTSOCKET);
    }

    buf = xfer_buf;
    bytestoread = xfer_blen;

    if(bytestoread && data->set.max_recv_speed > 0) {
      /* In case of speed limit on receiving: if this loop already got
       * data, break out. If not, limit the amount of bytes to receive.
       * The overall, timed, speed limiting is done in multi.c */
      if(total_received)
        break;
      if(data->set.max_recv_speed < (curl_off_t)bytestoread)
        bytestoread = (size_t)data->set.max_recv_speed;
    }

    nread = xfer_recv_resp(data, buf, bytestoread, is_multiplex, &result);
    if(nread < 0) {
      if(CURLE_AGAIN != result)
        goto out; /* real error */
      result = CURLE_OK;
      if(data->req.download_done && data->req.no_body &&
         !data->req.resp_trailer) {
        DEBUGF(infof(data, "EAGAIN, download done, no trailer announced, "
               "not waiting for EOS"));
        nread = 0;
        /* continue as if we read the EOS */
      }
      else
        break; /* get out of loop */
    }

    /* We only get a 0-length read on EndOfStream */
    blen = (size_t)nread;
    is_eos = (blen == 0);
    *didwhat |= KEEP_RECV;

    if(!blen) {
      /* if we receive 0 or less here, either the data transfer is done or the
         server closed the connection and we bail out from this! */
      if(is_multiplex)
        DEBUGF(infof(data, "nread == 0, stream closed, bailing"));
      else
        DEBUGF(infof(data, "nread <= 0, server closed connection, bailing"));
      result = Curl_req_stop_send_recv(data);
      if(result)
        goto out;
      if(k->eos_written) /* already did write this to client, leave */
        break;
    }
    total_received += blen;

    result = Curl_xfer_write_resp(data, buf, blen, is_eos);
    if(result || data->req.done)
      goto out;

    /* if we are done, we stop receiving. On multiplexed connections,
     * we should read the EOS. Which may arrive as meta data after
     * the bytes. Not taking it in might lead to RST of streams. */
    if((!is_multiplex && data->req.download_done) || is_eos) {
      data->req.keepon &= ~KEEP_RECV;
    }
    /* if we are PAUSEd or stopped receiving, leave the loop */
    if((k->keepon & KEEP_RECV_PAUSE) || !(k->keepon & KEEP_RECV))
      break;

  } while(maxloops--);

  if((maxloops <= 0) || data_pending(data)) {
    /* did not read until EAGAIN or there is still pending data, mark as
       read-again-please */
    data->state.select_bits = CURL_CSELECT_IN;
    if((k->keepon & KEEP_SENDBITS) == KEEP_SEND)
      data->state.select_bits |= CURL_CSELECT_OUT;
  }

  if(((k->keepon & (KEEP_RECV|KEEP_SEND)) == KEEP_SEND) &&
     (conn->bits.close || is_multiplex)) {
    /* When we have read the entire thing and the close bit is set, the server
       may now close the connection. If there is now any kind of sending going
       on from our side, we need to stop that immediately. */
    infof(data, "we are done reading and this is set to close, stop send");
    Curl_req_abort_sending(data);
  }

out:
  Curl_multi_xfer_buf_release(data, xfer_buf);
  if(result)
    DEBUGF(infof(data, "sendrecv_dl() -> %d", result));
  return result;
}

/*
 * Send data to upload to the server, when the socket is writable.
 */
static CURLcode sendrecv_ul(struct Curl_easy *data, int *didwhat)
{
  /* We should not get here when the sending is already done. It
   * probably means that someone set `data-req.keepon |= KEEP_SEND`
   * when it should not. */
  DEBUGASSERT(!Curl_req_done_sending(data));

  if(!Curl_req_done_sending(data)) {
    *didwhat |= KEEP_SEND;
    return Curl_req_send_more(data);
  }
  return CURLE_OK;
}

static int select_bits_paused(struct Curl_easy *data, int select_bits)
{
  /* See issue #11982: we really need to be careful not to progress
   * a transfer direction when that direction is paused. Not all parts
   * of our state machine are handling PAUSED transfers correctly. So, we
   * do not want to go there.
   * NOTE: we are only interested in PAUSE, not HOLD. */

  /* if there is data in a direction not paused, return false */
  if(((select_bits & CURL_CSELECT_IN) &&
      !(data->req.keepon & KEEP_RECV_PAUSE)) ||
     ((select_bits & CURL_CSELECT_OUT) &&
      !(data->req.keepon & KEEP_SEND_PAUSE)))
    return FALSE;

  return (data->req.keepon & (KEEP_RECV_PAUSE|KEEP_SEND_PAUSE));
}

/*
 * Curl_sendrecv() is the low-level function to be called when data is to
 * be read and written to/from the connection.
 */
CURLcode Curl_sendrecv(struct Curl_easy *data, struct curltime *nowp)
{
  struct SingleRequest *k = &data->req;
  CURLcode result = CURLE_OK;
  int didwhat = 0;

  DEBUGASSERT(nowp);
  if(data->state.select_bits) {
    if(select_bits_paused(data, data->state.select_bits)) {
      /* leave the bits unchanged, so they'll tell us what to do when
       * this transfer gets unpaused. */
      result = CURLE_OK;
      goto out;
    }
    data->state.select_bits = 0;
  }

  /* We go ahead and do a read if we have a readable socket or if the stream
     was rewound (in which case we have data in a buffer) */
  if(k->keepon & KEEP_RECV) {
    result = sendrecv_dl(data, k, &didwhat);
    if(result || data->req.done)
      goto out;
  }

  /* If we still have writing to do, we check if we have a writable socket. */
  if(Curl_req_want_send(data) || (data->req.keepon & KEEP_SEND_TIMED)) {
    result = sendrecv_ul(data, &didwhat);
    if(result)
      goto out;
  }

  if(!didwhat) {
    /* Transfer wanted to send/recv, but nothing was possible. */
    result = Curl_conn_ev_data_idle(data);
    if(result)
      goto out;
  }

  if(Curl_pgrsUpdate(data))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, *nowp);
  if(result)
    goto out;

  if(k->keepon) {
    if(0 > Curl_timeleft(data, nowp, FALSE)) {
      if(k->size != -1) {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " out of %"
              FMT_OFF_T " bytes received",
              Curl_timediff(*nowp, data->progress.t_startsingle),
              k->bytecount, k->size);
      }
      else {
        failf(data, "Operation timed out after %" FMT_TIMEDIFF_T
              " milliseconds with %" FMT_OFF_T " bytes received",
              Curl_timediff(*nowp, data->progress.t_startsingle),
              k->bytecount);
      }
      result = CURLE_OPERATION_TIMEDOUT;
      goto out;
    }
  }
  else {
    /*
     * The transfer has been performed. Just make some general checks before
     * returning.
     */
    if(!(data->req.no_body) && (k->size != -1) &&
       (k->bytecount != k->size) && !k->newurl) {
      failf(data, "transfer closed with %" FMT_OFF_T
            " bytes remaining to read", k->size - k->bytecount);
      result = CURLE_PARTIAL_FILE;
      goto out;
    }
    if(Curl_pgrsUpdate(data)) {
      result = CURLE_ABORTED_BY_CALLBACK;
      goto out;
    }
  }

  /* If there is nothing more to send/recv, the request is done */
  if(0 == (k->keepon&(KEEP_RECVBITS|KEEP_SENDBITS)))
    data->req.done = TRUE;

out:
  if(result)
    DEBUGF(infof(data, "Curl_sendrecv() -> %d", result));
  return result;
}

/* Curl_init_CONNECT() gets called each time the handle switches to CONNECT
   which means this gets called once for each subsequent redirect etc */
void Curl_init_CONNECT(struct Curl_easy *data)
{
  data->state.fread_func = data->set.fread_func_set;
  data->state.in = data->set.in_set;
  data->state.upload = (data->state.httpreq == HTTPREQ_PUT);
}

/*
 * Curl_pretransfer() is called immediately before a transfer starts, and only
 * once for one transfer no matter if it has redirects or do multi-pass
 * authentication etc.
 */
CURLcode Curl_pretransfer(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;

  if(!data->set.str[STRING_SET_URL] && !data->set.uh) {
    /* we cannot do anything without URL */
    failf(data, "No URL set");
    return CURLE_URL_MALFORMAT;
  }

  /* CURLOPT_CURLU overrides CURLOPT_URL and the contents of the CURLU handle
     is allowed to be changed by the user between transfers */
  if(data->set.uh) {
    CURLUcode uc;
    free(data->set.str[STRING_SET_URL]);
    uc = curl_url_get(data->set.uh,
                      CURLUPART_URL, &data->set.str[STRING_SET_URL], 0);
    if(uc) {
      failf(data, "No URL set");
      return CURLE_URL_MALFORMAT;
    }
  }

  /* since the URL may have been redirected in a previous use of this handle */
  if(data->state.url_alloc) {
    Curl_safefree(data->state.url);
    data->state.url_alloc = FALSE;
  }

  data->state.url = data->set.str[STRING_SET_URL];

  if(data->set.postfields && data->set.set_resume_from) {
    /* we cannot */
    failf(data, "cannot mix POSTFIELDS with RESUME_FROM");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  data->state.prefer_ascii = data->set.prefer_ascii;
#ifdef CURL_LIST_ONLY_PROTOCOL
  data->state.list_only = data->set.list_only;
#endif
  data->state.httpreq = data->set.method;

  data->state.requests = 0;
  data->state.followlocation = 0; /* reset the location-follow counter */
  data->state.this_is_a_follow = FALSE; /* reset this */
  data->state.errorbuf = FALSE; /* no error has occurred */
#ifndef CURL_DISABLE_HTTP
  Curl_http_neg_init(data, &data->state.http_neg);
#endif
  data->state.authproblem = FALSE;
  data->state.authhost.want = data->set.httpauth;
  data->state.authproxy.want = data->set.proxyauth;
  Curl_safefree(data->info.wouldredirect);
  Curl_data_priority_clear_state(data);

  if(data->state.httpreq == HTTPREQ_PUT)
    data->state.infilesize = data->set.filesize;
  else if((data->state.httpreq != HTTPREQ_GET) &&
          (data->state.httpreq != HTTPREQ_HEAD)) {
    data->state.infilesize = data->set.postfieldsize;
    if(data->set.postfields && (data->state.infilesize == -1))
      data->state.infilesize = (curl_off_t)strlen(data->set.postfields);
  }
  else
    data->state.infilesize = 0;

  /* If there is a list of cookie files to read, do it now! */
  Curl_cookie_loadfiles(data);

  /* If there is a list of host pairs to deal with */
  if(data->state.resolve)
    result = Curl_loadhostpairs(data);

  /* If there is a list of hsts files to read */
  Curl_hsts_loadfiles(data);

  if(!result) {
    /* Allow data->set.use_port to set which port to use. This needs to be
     * disabled for example when we follow Location: headers to URLs using
     * different ports! */
    data->state.allow_port = TRUE;

#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
    /*************************************************************
     * Tell signal handler to ignore SIGPIPE
     *************************************************************/
    if(!data->set.no_signal)
      data->state.prev_signal = signal(SIGPIPE, SIG_IGN);
#endif

    Curl_initinfo(data); /* reset session-specific information "variables" */
    Curl_pgrsResetTransferSizes(data);
    Curl_pgrsStartNow(data);

    /* In case the handle is reused and an authentication method was picked
       in the session we need to make sure we only use the one(s) we now
       consider to be fine */
    data->state.authhost.picked &= data->state.authhost.want;
    data->state.authproxy.picked &= data->state.authproxy.want;

#ifndef CURL_DISABLE_FTP
    data->state.wildcardmatch = data->set.wildcard_enabled;
    if(data->state.wildcardmatch) {
      struct WildcardData *wc;
      if(!data->wildcard) {
        data->wildcard = calloc(1, sizeof(struct WildcardData));
        if(!data->wildcard)
          return CURLE_OUT_OF_MEMORY;
      }
      wc = data->wildcard;
      if(wc->state < CURLWC_INIT) {
        if(wc->ftpwc)
          wc->dtor(wc->ftpwc);
        Curl_safefree(wc->pattern);
        Curl_safefree(wc->path);
        result = Curl_wildcard_init(wc); /* init wildcard structures */
        if(result)
          return CURLE_OUT_OF_MEMORY;
      }
    }
#endif
    result = Curl_hsts_loadcb(data, data->hsts);
  }

  /*
   * Set user-agent. Used for HTTP, but since we can attempt to tunnel
   * basically anything through an HTTP proxy we cannot limit this based on
   * protocol.
   */
  if(data->set.str[STRING_USERAGENT]) {
    free(data->state.aptr.uagent);
    data->state.aptr.uagent =
      aprintf("User-Agent: %s\r\n", data->set.str[STRING_USERAGENT]);
    if(!data->state.aptr.uagent)
      return CURLE_OUT_OF_MEMORY;
  }

  if(data->set.str[STRING_USERNAME] ||
     data->set.str[STRING_PASSWORD])
    data->state.creds_from = CREDS_OPTION;
  if(!result)
    result = Curl_setstropt(&data->state.aptr.user,
                            data->set.str[STRING_USERNAME]);
  if(!result)
    result = Curl_setstropt(&data->state.aptr.passwd,
                            data->set.str[STRING_PASSWORD]);
#ifndef CURL_DISABLE_PROXY
  if(!result)
    result = Curl_setstropt(&data->state.aptr.proxyuser,
                            data->set.str[STRING_PROXYUSERNAME]);
  if(!result)
    result = Curl_setstropt(&data->state.aptr.proxypasswd,
                            data->set.str[STRING_PROXYPASSWORD]);
#endif

  data->req.headerbytecount = 0;
  Curl_headers_cleanup(data);
  return result;
}

/* Returns CURLE_OK *and* sets '*url' if a request retry is wanted.

   NOTE: that the *url is malloc()ed. */
CURLcode Curl_retry_request(struct Curl_easy *data, char **url)
{
  struct connectdata *conn = data->conn;
  bool retry = FALSE;
  *url = NULL;

  /* if we are talking upload, we cannot do the checks below, unless the
     protocol is HTTP as when uploading over HTTP we will still get a
     response */
  if(data->state.upload &&
     !(conn->handler->protocol&(PROTO_FAMILY_HTTP|CURLPROTO_RTSP)))
    return CURLE_OK;

  if((data->req.bytecount + data->req.headerbytecount == 0) &&
     conn->bits.reuse &&
     (!data->req.no_body || (conn->handler->protocol & PROTO_FAMILY_HTTP))
#ifndef CURL_DISABLE_RTSP
     && (data->set.rtspreq != RTSPREQ_RECEIVE)
#endif
    )
    /* We got no data, we attempted to reuse a connection. For HTTP this
       can be a retry so we try again regardless if we expected a body.
       For other protocols we only try again only if we expected a body.

       This might happen if the connection was left alive when we were
       done using it before, but that was closed when we wanted to read from
       it again. Bad luck. Retry the same request on a fresh connect! */
    retry = TRUE;
  else if(data->state.refused_stream &&
          (data->req.bytecount + data->req.headerbytecount == 0) ) {
    /* This was sent on a refused stream, safe to rerun. A refused stream
       error can typically only happen on HTTP/2 level if the stream is safe
       to issue again, but the nghttp2 API can deliver the message to other
       streams as well, which is why this adds the check the data counters
       too. */
    infof(data, "REFUSED_STREAM, retrying a fresh connect");
    data->state.refused_stream = FALSE; /* clear again */
    retry = TRUE;
  }
  if(retry) {
#define CONN_MAX_RETRIES 5
    if(data->state.retrycount++ >= CONN_MAX_RETRIES) {
      failf(data, "Connection died, tried %d times before giving up",
            CONN_MAX_RETRIES);
      data->state.retrycount = 0;
      return CURLE_SEND_ERROR;
    }
    infof(data, "Connection died, retrying a fresh connect (retry count: %d)",
          data->state.retrycount);
    *url = strdup(data->state.url);
    if(!*url)
      return CURLE_OUT_OF_MEMORY;

    connclose(conn, "retry"); /* close this connection */
    conn->bits.retry = TRUE; /* mark this as a connection we are about
                                to retry. Marking it this way should
                                prevent i.e HTTP transfers to return
                                error just because nothing has been
                                transferred! */
    Curl_creader_set_rewind(data, TRUE);
  }
  return CURLE_OK;
}

/*
 * xfer_setup() is called to setup basic properties for the transfer.
 */
static void xfer_setup(
  struct Curl_easy *data,   /* transfer */
  int sockindex,            /* socket index to read from or -1 */
  curl_off_t size,          /* -1 if unknown at this point */
  bool getheader,           /* TRUE if header parsing is wanted */
  int writesockindex,       /* socket index to write to, it may be the same we
                               read from. -1 disables */
  bool shutdown,            /* shutdown connection at transfer end. Only
                             * supported when sending OR receiving. */
  bool shutdown_err_ignore  /* errors during shutdown do not fail the
                             * transfer */
  )
{
  struct SingleRequest *k = &data->req;
  struct connectdata *conn = data->conn;
  bool want_send = Curl_req_want_send(data);

  DEBUGASSERT(conn != NULL);
  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
  DEBUGASSERT((writesockindex <= 1) && (writesockindex >= -1));
  DEBUGASSERT(!shutdown || (sockindex == -1) || (writesockindex == -1));

  if(Curl_conn_is_multiplex(conn, FIRSTSOCKET) || want_send) {
    /* when multiplexing, the read/write sockets need to be the same! */
    conn->sockfd = sockindex == -1 ?
      ((writesockindex == -1 ? CURL_SOCKET_BAD : conn->sock[writesockindex])) :
      conn->sock[sockindex];
    conn->writesockfd = conn->sockfd;
    if(want_send)
      /* special and HTTP-specific */
      writesockindex = FIRSTSOCKET;
  }
  else {
    conn->sockfd = sockindex == -1 ?
      CURL_SOCKET_BAD : conn->sock[sockindex];
    conn->writesockfd = writesockindex == -1 ?
      CURL_SOCKET_BAD : conn->sock[writesockindex];
  }

  k->getheader = getheader;
  k->size = size;
  k->shutdown = shutdown;
  k->shutdown_err_ignore = shutdown_err_ignore;

  /* The code sequence below is placed in this function just because all
     necessary input is not always known in do_complete() as this function may
     be called after that */

  if(!k->getheader) {
    k->header = FALSE;
    if(size > 0)
      Curl_pgrsSetDownloadSize(data, size);
  }
  /* we want header and/or body, if neither then do not do this! */
  if(k->getheader || !data->req.no_body) {

    if(sockindex != -1)
      k->keepon |= KEEP_RECV;

    if(writesockindex != -1)
      k->keepon |= KEEP_SEND;
  } /* if(k->getheader || !data->req.no_body) */

}

void Curl_xfer_setup_nop(struct Curl_easy *data)
{
  xfer_setup(data, -1, -1, FALSE, -1, FALSE, FALSE);
}

void Curl_xfer_setup1(struct Curl_easy *data,
                      int send_recv,
                      curl_off_t recv_size,
                      bool getheader)
{
  int recv_index = (send_recv & CURL_XFER_RECV) ? FIRSTSOCKET : -1;
  int send_index = (send_recv & CURL_XFER_SEND) ? FIRSTSOCKET : -1;
  DEBUGASSERT((recv_index >= 0) || (recv_size == -1));
  xfer_setup(data, recv_index, recv_size, getheader, send_index, FALSE, FALSE);
}

void Curl_xfer_setup2(struct Curl_easy *data,
                      int send_recv,
                      curl_off_t recv_size,
                      bool shutdown,
                      bool shutdown_err_ignore)
{
  int recv_index = (send_recv & CURL_XFER_RECV) ? SECONDARYSOCKET : -1;
  int send_index = (send_recv & CURL_XFER_SEND) ? SECONDARYSOCKET : -1;
  DEBUGASSERT((recv_index >= 0) || (recv_size == -1));
  xfer_setup(data, recv_index, recv_size, FALSE, send_index,
             shutdown, shutdown_err_ignore);
}

CURLcode Curl_xfer_write_resp(struct Curl_easy *data,
                              const char *buf, size_t blen,
                              bool is_eos)
{
  CURLcode result = CURLE_OK;

  if(data->conn->handler->write_resp) {
    /* protocol handlers offering this function take full responsibility
     * for writing all received download data to the client. */
    result = data->conn->handler->write_resp(data, buf, blen, is_eos);
  }
  else {
    /* No special handling by protocol handler, write all received data
     * as BODY to the client. */
    if(blen || is_eos) {
      int cwtype = CLIENTWRITE_BODY;
      if(is_eos)
        cwtype |= CLIENTWRITE_EOS;
      result = Curl_client_write(data, cwtype, buf, blen);
    }
  }

  if(!result && is_eos) {
    /* If we wrote the EOS, we are definitely done */
    data->req.eos_written = TRUE;
    data->req.download_done = TRUE;
  }
  CURL_TRC_WRITE(data, "xfer_write_resp(len=%zu, eos=%d) -> %d",
                 blen, is_eos, result);
  return result;
}

bool Curl_xfer_write_is_paused(struct Curl_easy *data)
{
  return Curl_cwriter_is_paused(data);
}

CURLcode Curl_xfer_write_resp_hd(struct Curl_easy *data,
                                 const char *hd0, size_t hdlen, bool is_eos)
{
  if(data->conn->handler->write_resp_hd) {
    /* protocol handlers offering this function take full responsibility
     * for writing all received download data to the client. */
    return data->conn->handler->write_resp_hd(data, hd0, hdlen, is_eos);
  }
  /* No special handling by protocol handler, write as response bytes */
  return Curl_xfer_write_resp(data, hd0, hdlen, is_eos);
}

CURLcode Curl_xfer_write_done(struct Curl_easy *data, bool premature)
{
  (void)premature;
  return Curl_cw_out_done(data);
}

bool Curl_xfer_needs_flush(struct Curl_easy *data)
{
  int sockindex;
  sockindex = ((data->conn->writesockfd != CURL_SOCKET_BAD) &&
               (data->conn->writesockfd == data->conn->sock[SECONDARYSOCKET]));
  return Curl_conn_needs_flush(data, sockindex);
}

CURLcode Curl_xfer_flush(struct Curl_easy *data)
{
  int sockindex;
  sockindex = ((data->conn->writesockfd != CURL_SOCKET_BAD) &&
               (data->conn->writesockfd == data->conn->sock[SECONDARYSOCKET]));
  return Curl_conn_flush(data, sockindex);
}

CURLcode Curl_xfer_send(struct Curl_easy *data,
                        const void *buf, size_t blen, bool eos,
                        size_t *pnwritten)
{
  CURLcode result;
  int sockindex;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);

  sockindex = ((data->conn->writesockfd != CURL_SOCKET_BAD) &&
               (data->conn->writesockfd == data->conn->sock[SECONDARYSOCKET]));
  result = Curl_conn_send(data, sockindex, buf, blen, eos, pnwritten);
  if(result == CURLE_AGAIN) {
    result = CURLE_OK;
    *pnwritten = 0;
  }
  else if(!result && *pnwritten)
    data->info.request_size += *pnwritten;

  DEBUGF(infof(data, "Curl_xfer_send(len=%zu, eos=%d) -> %d, %zu",
               blen, eos, result, *pnwritten));
  return result;
}

CURLcode Curl_xfer_recv(struct Curl_easy *data,
                        char *buf, size_t blen,
                        ssize_t *pnrcvd)
{
  int sockindex;

  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  DEBUGASSERT(data->set.buffer_size > 0);

  sockindex = ((data->conn->sockfd != CURL_SOCKET_BAD) &&
               (data->conn->sockfd == data->conn->sock[SECONDARYSOCKET]));
  if((size_t)data->set.buffer_size < blen)
    blen = (size_t)data->set.buffer_size;
  return Curl_conn_recv(data, sockindex, buf, blen, pnrcvd);
}

CURLcode Curl_xfer_send_close(struct Curl_easy *data)
{
  Curl_conn_ev_data_done_send(data);
  return CURLE_OK;
}

bool Curl_xfer_is_blocked(struct Curl_easy *data)
{
  bool want_send = ((data)->req.keepon & KEEP_SEND);
  bool want_recv = ((data)->req.keepon & KEEP_RECV);
  if(!want_send)
    return want_recv && Curl_cwriter_is_paused(data);
  else if(!want_recv)
    return want_send && Curl_creader_is_paused(data);
  else
    return Curl_creader_is_paused(data) && Curl_cwriter_is_paused(data);
}
