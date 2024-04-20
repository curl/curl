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
#include "strtoofft.h"

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
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#ifndef HAVE_SOCKET
#error "We can't compile without socket() support!"
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
#include "urlapi-int.h"
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

/**
 * Receive raw response data for the transfer.
 * @param data         the transfer
 * @param buf          buffer to keep response data received
 * @param blen         length of `buf`
 * @param eos_reliable if EOS detection in underlying connection is reliable
 * @param err error    code in case of -1 return
 * @return number of bytes read or -1 for error
 */
static ssize_t Curl_xfer_recv_resp(struct Curl_easy *data,
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

  if(!blen) {
    /* want nothing - continue as if read nothing. */
    DEBUGF(infof(data, "readwrite_data: we're done"));
    *err = CURLE_OK;
    return 0;
  }

  *err = Curl_xfer_recv(data, buf, blen, &nread);
  if(*err)
    return -1;
  DEBUGASSERT(nread >= 0);
  return nread;
}

/*
 * Go ahead and do a read if we have a readable socket or if
 * the stream was rewound (in which case we have data in a
 * buffer)
 */
static CURLcode readwrite_data(struct Curl_easy *data,
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

    if(bytestoread && data->set.max_recv_speed) {
      /* In case of speed limit on receiving: if this loop already got
       * data, break out. If not, limit the amount of bytes to receive.
       * The overall, timed, speed limiting is done in multi.c */
      if(total_received)
        break;
      if((size_t)data->set.max_recv_speed < bytestoread)
        bytestoread = (size_t)data->set.max_recv_speed;
    }

    nread = Curl_xfer_recv_resp(data, buf, bytestoread,
                                is_multiplex, &result);
    if(nread < 0) {
      if(CURLE_AGAIN == result) {
        result = CURLE_OK;
        break; /* get out of loop */
      }
      goto out; /* real error */
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
      k->keepon &= ~(KEEP_RECV|KEEP_SEND); /* stop sending as well */
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

  } while(maxloops-- && data_pending(data));

  if(maxloops <= 0) {
    /* did not read until EAGAIN, mark read-again-please */
    data->state.select_bits = CURL_CSELECT_IN;
    if((k->keepon & KEEP_SENDBITS) == KEEP_SEND)
      data->state.select_bits |= CURL_CSELECT_OUT;
  }

  if(((k->keepon & (KEEP_RECV|KEEP_SEND)) == KEEP_SEND) &&
     (conn->bits.close || is_multiplex)) {
    /* When we've read the entire thing and the close bit is set, the server
       may now close the connection. If there's now any kind of sending going
       on from our side, we need to stop that immediately. */
    infof(data, "we are done reading and this is set to close, stop send");
    k->keepon &= ~KEEP_SEND; /* no writing anymore either */
    k->keepon &= ~KEEP_SEND_PAUSE; /* no pausing anymore either */
  }

out:
  Curl_multi_xfer_buf_release(data, xfer_buf);
  if(result)
    DEBUGF(infof(data, "readwrite_data() -> %d", result));
  return result;
}

#if defined(_WIN32) && defined(USE_WINSOCK)
#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747B
#endif

static void win_update_buffer_size(curl_socket_t sockfd)
{
  int result;
  ULONG ideal;
  DWORD ideallen;
  result = WSAIoctl(sockfd, SIO_IDEAL_SEND_BACKLOG_QUERY, 0, 0,
                    &ideal, sizeof(ideal), &ideallen, 0, 0);
  if(result == 0) {
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
               (const char *)&ideal, sizeof(ideal));
  }
}
#else
#define win_update_buffer_size(x)
#endif

#define curl_upload_refill_watermark(data) \
        ((size_t)((data)->set.upload_buffer_size >> 5))

/*
 * Send data to upload to the server, when the socket is writable.
 */
static CURLcode readwrite_upload(struct Curl_easy *data, int *didwhat)
{
  CURLcode result = CURLE_OK;

  if((data->req.keepon & KEEP_SEND_PAUSE))
    return CURLE_OK;

  /* We should not get here when the sending is already done. It
   * probably means that someone set `data-req.keepon |= KEEP_SEND`
   * when it should not. */
  DEBUGASSERT(!Curl_req_done_sending(data));

  if(!Curl_req_done_sending(data)) {
    *didwhat |= KEEP_SEND;
    result = Curl_req_send_more(data);
    if(result)
      return result;

#if defined(_WIN32) && defined(USE_WINSOCK)
    /* FIXME: this looks like it would fit better into cf-socket.c
     * but then I do not know enough Windows to say... */
    {
      struct curltime n = Curl_now();
      if(Curl_timediff(n, data->conn->last_sndbuf_update) > 1000) {
        win_update_buffer_size(data->conn->writesockfd);
        data->conn->last_sndbuf_update = n;
      }
    }
#endif
  }
  return result;
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
 * Curl_readwrite() is the low-level function to be called when data is to
 * be read and written to/from the connection.
 */
CURLcode Curl_readwrite(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  struct SingleRequest *k = &data->req;
  CURLcode result;
  struct curltime now;
  int didwhat = 0;
  int select_bits;

  /* Check if client writes had been paused and can resume now. */
  if(!(k->keepon & KEEP_RECV_PAUSE) && Curl_cwriter_is_paused(data)) {
    Curl_conn_ev_data_pause(data, FALSE);
    result = Curl_cwriter_unpause(data);
    if(result)
      goto out;
  }

  if(data->state.select_bits) {
    if(select_bits_paused(data, data->state.select_bits)) {
      /* leave the bits unchanged, so they'll tell us what to do when
       * this transfer gets unpaused. */
      DEBUGF(infof(data, "readwrite, select_bits, early return on PAUSED"));
      result = CURLE_OK;
      goto out;
    }
    select_bits = data->state.select_bits;
    data->state.select_bits = 0;
  }
  else {
    curl_socket_t fd_read;
    curl_socket_t fd_write;
    /* only use the proper socket if the *_HOLD bit is not set simultaneously
       as then we are in rate limiting state in that transfer direction */
    if((k->keepon & KEEP_RECVBITS) == KEEP_RECV)
      fd_read = conn->sockfd;
    else
      fd_read = CURL_SOCKET_BAD;

    if((k->keepon & KEEP_SENDBITS) == KEEP_SEND)
      fd_write = conn->writesockfd;
    else
      fd_write = CURL_SOCKET_BAD;

    select_bits = Curl_socket_check(fd_read, CURL_SOCKET_BAD, fd_write, 0);
  }

  if(select_bits == CURL_CSELECT_ERR) {
    failf(data, "select/poll returned error");
    result = CURLE_SEND_ERROR;
    goto out;
  }

#ifdef USE_HYPER
  if(conn->datastream) {
    result = conn->datastream(data, conn, &didwhat, select_bits);
    if(result || data->req.done)
      goto out;
  }
  else {
#endif
  /* We go ahead and do a read if we have a readable socket or if
     the stream was rewound (in which case we have data in a
     buffer) */
  if((k->keepon & KEEP_RECV) && (select_bits & CURL_CSELECT_IN)) {
    result = readwrite_data(data, k, &didwhat);
    if(result || data->req.done)
      goto out;
  }

  /* If we still have writing to do, we check if we have a writable socket. */
  if(((k->keepon & KEEP_SEND) && (select_bits & CURL_CSELECT_OUT)) ||
     (k->keepon & KEEP_SEND_TIMED)) {
    /* write */

    result = readwrite_upload(data, &didwhat);
    if(result)
      goto out;
  }
#ifdef USE_HYPER
  }
#endif

  now = Curl_now();
  if(!didwhat) {
    result = Curl_conn_ev_data_idle(data);
    if(result)
      goto out;
  }

  if(Curl_pgrsUpdate(data))
    result = CURLE_ABORTED_BY_CALLBACK;
  else
    result = Curl_speedcheck(data, now);
  if(result)
    goto out;

  if(k->keepon) {
    if(0 > Curl_timeleft(data, &now, FALSE)) {
      if(k->size != -1) {
        failf(data, "Operation timed out after %" CURL_FORMAT_TIMEDIFF_T
              " milliseconds with %" CURL_FORMAT_CURL_OFF_T " out of %"
              CURL_FORMAT_CURL_OFF_T " bytes received",
              Curl_timediff(now, data->progress.t_startsingle),
              k->bytecount, k->size);
      }
      else {
        failf(data, "Operation timed out after %" CURL_FORMAT_TIMEDIFF_T
              " milliseconds with %" CURL_FORMAT_CURL_OFF_T " bytes received",
              Curl_timediff(now, data->progress.t_startsingle),
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
       (k->bytecount != k->size) &&
#ifdef CURL_DO_LINEEND_CONV
       /* Most FTP servers don't adjust their file SIZE response for CRLFs,
          so we'll check to see if the discrepancy can be explained
          by the number of CRLFs we've changed to LFs.
       */
       (k->bytecount != (k->size + data->state.crlf_conversions)) &&
#endif /* CURL_DO_LINEEND_CONV */
       !k->newurl) {
      failf(data, "transfer closed with %" CURL_FORMAT_CURL_OFF_T
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
    DEBUGF(infof(data, "Curl_readwrite() -> %d", result));
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
  CURLcode result;

  if(!data->state.url && !data->set.uh) {
    /* we can't do anything without URL */
    failf(data, "No URL set");
    return CURLE_URL_MALFORMAT;
  }

  /* since the URL may have been redirected in a previous use of this handle */
  if(data->state.url_alloc) {
    /* the already set URL is allocated, free it first! */
    Curl_safefree(data->state.url);
    data->state.url_alloc = FALSE;
  }

  if(!data->state.url && data->set.uh) {
    CURLUcode uc;
    free(data->set.str[STRING_SET_URL]);
    uc = curl_url_get(data->set.uh,
                      CURLUPART_URL, &data->set.str[STRING_SET_URL], 0);
    if(uc) {
      failf(data, "No URL set");
      return CURLE_URL_MALFORMAT;
    }
  }

  if(data->set.postfields && data->set.set_resume_from) {
    /* we can't */
    failf(data, "cannot mix POSTFIELDS with RESUME_FROM");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  data->state.prefer_ascii = data->set.prefer_ascii;
#ifdef CURL_LIST_ONLY_PROTOCOL
  data->state.list_only = data->set.list_only;
#endif
  data->state.httpreq = data->set.method;
  data->state.url = data->set.str[STRING_SET_URL];

  /* Init the SSL session ID cache here. We do it here since we want to do it
     after the *_setopt() calls (that could specify the size of the cache) but
     before any transfer takes place. */
  result = Curl_ssl_initsessions(data, data->set.general_ssl.max_ssl_sessions);
  if(result)
    return result;

  data->state.requests = 0;
  data->state.followlocation = 0; /* reset the location-follow counter */
  data->state.this_is_a_follow = FALSE; /* reset this */
  data->state.errorbuf = FALSE; /* no error has occurred */
  data->state.httpwant = data->set.httpwant;
  data->state.httpversion = 0;
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
   * basically anything through an HTTP proxy we can't limit this based on
   * protocol.
   */
  if(data->set.str[STRING_USERAGENT]) {
    Curl_safefree(data->state.aptr.uagent);
    data->state.aptr.uagent =
      aprintf("User-Agent: %s\r\n", data->set.str[STRING_USERAGENT]);
    if(!data->state.aptr.uagent)
      return CURLE_OUT_OF_MEMORY;
  }

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

/*
 * Curl_posttransfer() is called immediately after a transfer ends
 */
CURLcode Curl_posttransfer(struct Curl_easy *data)
{
#if defined(HAVE_SIGNAL) && defined(SIGPIPE) && !defined(HAVE_MSG_NOSIGNAL)
  /* restore the signal handler for SIGPIPE before we get back */
  if(!data->set.no_signal)
    signal(SIGPIPE, data->state.prev_signal);
#else
  (void)data; /* unused parameter */
#endif

  return CURLE_OK;
}

/*
 * Curl_follow() handles the URL redirect magic. Pass in the 'newurl' string
 * as given by the remote server and set up the new URL to request.
 *
 * This function DOES NOT FREE the given url.
 */
CURLcode Curl_follow(struct Curl_easy *data,
                     char *newurl,    /* the Location: string */
                     followtype type) /* see transfer.h */
{
#ifdef CURL_DISABLE_HTTP
  (void)data;
  (void)newurl;
  (void)type;
  /* Location: following will not happen when HTTP is disabled */
  return CURLE_TOO_MANY_REDIRECTS;
#else

  /* Location: redirect */
  bool disallowport = FALSE;
  bool reachedmax = FALSE;
  CURLUcode uc;

  DEBUGASSERT(type != FOLLOW_NONE);

  if(type != FOLLOW_FAKE)
    data->state.requests++; /* count all real follows */
  if(type == FOLLOW_REDIR) {
    if((data->set.maxredirs != -1) &&
       (data->state.followlocation >= data->set.maxredirs)) {
      reachedmax = TRUE;
      type = FOLLOW_FAKE; /* switch to fake to store the would-be-redirected
                             to URL */
    }
    else {
      data->state.followlocation++; /* count redirect-followings, including
                                       auth reloads */

      if(data->set.http_auto_referer) {
        CURLU *u;
        char *referer = NULL;

        /* We are asked to automatically set the previous URL as the referer
           when we get the next URL. We pick the ->url field, which may or may
           not be 100% correct */

        if(data->state.referer_alloc) {
          Curl_safefree(data->state.referer);
          data->state.referer_alloc = FALSE;
        }

        /* Make a copy of the URL without credentials and fragment */
        u = curl_url();
        if(!u)
          return CURLE_OUT_OF_MEMORY;

        uc = curl_url_set(u, CURLUPART_URL, data->state.url, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_FRAGMENT, NULL, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_USER, NULL, 0);
        if(!uc)
          uc = curl_url_set(u, CURLUPART_PASSWORD, NULL, 0);
        if(!uc)
          uc = curl_url_get(u, CURLUPART_URL, &referer, 0);

        curl_url_cleanup(u);

        if(uc || !referer)
          return CURLE_OUT_OF_MEMORY;

        data->state.referer = referer;
        data->state.referer_alloc = TRUE; /* yes, free this later */
      }
    }
  }

  if((type != FOLLOW_RETRY) &&
     (data->req.httpcode != 401) && (data->req.httpcode != 407) &&
     Curl_is_absolute_url(newurl, NULL, 0, FALSE)) {
    /* If this is not redirect due to a 401 or 407 response and an absolute
       URL: don't allow a custom port number */
    disallowport = TRUE;
  }

  DEBUGASSERT(data->state.uh);
  uc = curl_url_set(data->state.uh, CURLUPART_URL, newurl,
                    (type == FOLLOW_FAKE) ? CURLU_NON_SUPPORT_SCHEME :
                    ((type == FOLLOW_REDIR) ? CURLU_URLENCODE : 0) |
                    CURLU_ALLOW_SPACE |
                    (data->set.path_as_is ? CURLU_PATH_AS_IS : 0));
  if(uc) {
    if(type != FOLLOW_FAKE) {
      failf(data, "The redirect target URL could not be parsed: %s",
            curl_url_strerror(uc));
      return Curl_uc_to_curlcode(uc);
    }

    /* the URL could not be parsed for some reason, but since this is FAKE
       mode, just duplicate the field as-is */
    newurl = strdup(newurl);
    if(!newurl)
      return CURLE_OUT_OF_MEMORY;
  }
  else {
    uc = curl_url_get(data->state.uh, CURLUPART_URL, &newurl, 0);
    if(uc)
      return Curl_uc_to_curlcode(uc);

    /* Clear auth if this redirects to a different port number or protocol,
       unless permitted */
    if(!data->set.allow_auth_to_other_hosts && (type != FOLLOW_FAKE)) {
      char *portnum;
      int port;
      bool clear = FALSE;

      if(data->set.use_port && data->state.allow_port)
        /* a custom port is used */
        port = (int)data->set.use_port;
      else {
        uc = curl_url_get(data->state.uh, CURLUPART_PORT, &portnum,
                          CURLU_DEFAULT_PORT);
        if(uc) {
          free(newurl);
          return Curl_uc_to_curlcode(uc);
        }
        port = atoi(portnum);
        free(portnum);
      }
      if(port != data->info.conn_remote_port) {
        infof(data, "Clear auth, redirects to port from %u to %u",
              data->info.conn_remote_port, port);
        clear = TRUE;
      }
      else {
        char *scheme;
        const struct Curl_handler *p;
        uc = curl_url_get(data->state.uh, CURLUPART_SCHEME, &scheme, 0);
        if(uc) {
          free(newurl);
          return Curl_uc_to_curlcode(uc);
        }

        p = Curl_get_scheme_handler(scheme);
        if(p && (p->protocol != data->info.conn_protocol)) {
          infof(data, "Clear auth, redirects scheme from %s to %s",
                data->info.conn_scheme, scheme);
          clear = TRUE;
        }
        free(scheme);
      }
      if(clear) {
        Curl_safefree(data->state.aptr.user);
        Curl_safefree(data->state.aptr.passwd);
      }
    }
  }

  if(type == FOLLOW_FAKE) {
    /* we're only figuring out the new url if we would've followed locations
       but now we're done so we can get out! */
    data->info.wouldredirect = newurl;

    if(reachedmax) {
      failf(data, "Maximum (%ld) redirects followed", data->set.maxredirs);
      return CURLE_TOO_MANY_REDIRECTS;
    }
    return CURLE_OK;
  }

  if(disallowport)
    data->state.allow_port = FALSE;

  if(data->state.url_alloc)
    Curl_safefree(data->state.url);

  data->state.url = newurl;
  data->state.url_alloc = TRUE;
  Curl_req_soft_reset(&data->req, data);
  infof(data, "Issue another request to this URL: '%s'", data->state.url);

  /*
   * We get here when the HTTP code is 300-399 (and 401). We need to perform
   * differently based on exactly what return code there was.
   *
   * News from 7.10.6: we can also get here on a 401 or 407, in case we act on
   * an HTTP (proxy-) authentication scheme other than Basic.
   */
  switch(data->info.httpcode) {
    /* 401 - Act on a WWW-Authenticate, we keep on moving and do the
       Authorization: XXXX header in the HTTP request code snippet */
    /* 407 - Act on a Proxy-Authenticate, we keep on moving and do the
       Proxy-Authorization: XXXX header in the HTTP request code snippet */
    /* 300 - Multiple Choices */
    /* 306 - Not used */
    /* 307 - Temporary Redirect */
  default:  /* for all above (and the unknown ones) */
    /* Some codes are explicitly mentioned since I've checked RFC2616 and they
     * seem to be OK to POST to.
     */
    break;
  case 301: /* Moved Permanently */
    /* (quote from RFC7231, section 6.4.2)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request.  If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behavior is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->state.httpreq == HTTPREQ_POST
        || data->state.httpreq == HTTPREQ_POST_FORM
        || data->state.httpreq == HTTPREQ_POST_MIME)
       && !(data->set.keep_post & CURL_REDIR_POST_301)) {
      infof(data, "Switch from POST to GET");
      data->state.httpreq = HTTPREQ_GET;
      Curl_creader_set_rewind(data, FALSE);
    }
    break;
  case 302: /* Found */
    /* (quote from RFC7231, section 6.4.3)
     *
     * Note: For historical reasons, a user agent MAY change the request
     * method from POST to GET for the subsequent request.  If this
     * behavior is undesired, the 307 (Temporary Redirect) status code
     * can be used instead.
     *
     * ----
     *
     * Many webservers expect this, so these servers often answers to a POST
     * request with an error page. To be sure that libcurl gets the page that
     * most user agents would get, libcurl has to force GET.
     *
     * This behavior is forbidden by RFC1945 and the obsolete RFC2616, and
     * can be overridden with CURLOPT_POSTREDIR.
     */
    if((data->state.httpreq == HTTPREQ_POST
        || data->state.httpreq == HTTPREQ_POST_FORM
        || data->state.httpreq == HTTPREQ_POST_MIME)
       && !(data->set.keep_post & CURL_REDIR_POST_302)) {
      infof(data, "Switch from POST to GET");
      data->state.httpreq = HTTPREQ_GET;
      Curl_creader_set_rewind(data, FALSE);
    }
    break;

  case 303: /* See Other */
    /* 'See Other' location is not the resource but a substitute for the
     * resource. In this case we switch the method to GET/HEAD, unless the
     * method is POST and the user specified to keep it as POST.
     * https://github.com/curl/curl/issues/5237#issuecomment-614641049
     */
    if(data->state.httpreq != HTTPREQ_GET &&
       ((data->state.httpreq != HTTPREQ_POST &&
         data->state.httpreq != HTTPREQ_POST_FORM &&
         data->state.httpreq != HTTPREQ_POST_MIME) ||
        !(data->set.keep_post & CURL_REDIR_POST_303))) {
      data->state.httpreq = HTTPREQ_GET;
      infof(data, "Switch to %s",
            data->req.no_body?"HEAD":"GET");
    }
    break;
  case 304: /* Not Modified */
    /* 304 means we did a conditional request and it was "Not modified".
     * We shouldn't get any Location: header in this response!
     */
    break;
  case 305: /* Use Proxy */
    /* (quote from RFC2616, section 10.3.6):
     * "The requested resource MUST be accessed through the proxy given
     * by the Location field. The Location field gives the URI of the
     * proxy.  The recipient is expected to repeat this single request
     * via the proxy. 305 responses MUST only be generated by origin
     * servers."
     */
    break;
  }
  Curl_pgrsTime(data, TIMER_REDIRECT);
  Curl_pgrsResetTransferSizes(data);

  return CURLE_OK;
#endif /* CURL_DISABLE_HTTP */
}

/* Returns CURLE_OK *and* sets '*url' if a request retry is wanted.

   NOTE: that the *url is malloc()ed. */
CURLcode Curl_retry_request(struct Curl_easy *data, char **url)
{
  struct connectdata *conn = data->conn;
  bool retry = FALSE;
  *url = NULL;

  /* if we're talking upload, we can't do the checks below, unless the protocol
     is HTTP as when uploading over HTTP we will still get a response */
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
    conn->bits.retry = TRUE; /* mark this as a connection we're about
                                to retry. Marking it this way should
                                prevent i.e HTTP transfers to return
                                error just because nothing has been
                                transferred! */
    Curl_creader_set_rewind(data, TRUE);
  }
  return CURLE_OK;
}

/*
 * Curl_xfer_setup() is called to setup some basic properties for the
 * upcoming transfer.
 */
void Curl_xfer_setup(
  struct Curl_easy *data,   /* transfer */
  int sockindex,            /* socket index to read from or -1 */
  curl_off_t size,          /* -1 if unknown at this point */
  bool getheader,           /* TRUE if header parsing is wanted */
  int writesockindex        /* socket index to write to, it may very well be
                               the same we read from. -1 disables */
  )
{
  struct SingleRequest *k = &data->req;
  struct connectdata *conn = data->conn;
  bool want_send = Curl_req_want_send(data);

  DEBUGASSERT(conn != NULL);
  DEBUGASSERT((sockindex <= 1) && (sockindex >= -1));
  DEBUGASSERT((writesockindex <= 1) && (writesockindex >= -1));

  if(conn->bits.multiplex || conn->httpversion >= 20 || want_send) {
    /* when multiplexing, the read/write sockets need to be the same! */
    conn->sockfd = sockindex == -1 ?
      ((writesockindex == -1 ? CURL_SOCKET_BAD : conn->sock[writesockindex])) :
      conn->sock[sockindex];
    conn->writesockfd = conn->sockfd;
    if(want_send)
      /* special and very HTTP-specific */
      writesockindex = FIRSTSOCKET;
  }
  else {
    conn->sockfd = sockindex == -1 ?
      CURL_SOCKET_BAD : conn->sock[sockindex];
    conn->writesockfd = writesockindex == -1 ?
      CURL_SOCKET_BAD:conn->sock[writesockindex];
  }
  k->getheader = getheader;

  k->size = size;

  /* The code sequence below is placed in this function just because all
     necessary input is not always known in do_complete() as this function may
     be called after that */

  if(!k->getheader) {
    k->header = FALSE;
    if(size > 0)
      Curl_pgrsSetDownloadSize(data, size);
  }
  /* we want header and/or body, if neither then don't do this! */
  if(k->getheader || !data->req.no_body) {

    if(sockindex != -1)
      k->keepon |= KEEP_RECV;

    if(writesockindex != -1)
      k->keepon |= KEEP_SEND;
  } /* if(k->getheader || !data->req.no_body) */

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

#ifndef CURL_DISABLE_POP3
      if(blen && data->conn->handler->protocol & PROTO_FAMILY_POP3) {
        result = data->req.ignorebody? CURLE_OK :
                 Curl_pop3_write(data, buf, blen);
      }
      else
#endif /* CURL_DISABLE_POP3 */
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

CURLcode Curl_xfer_send(struct Curl_easy *data,
                        const void *buf, size_t blen,
                        size_t *pnwritten)
{
  CURLcode result;
  int sockindex;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  /* FIXME: would like to enable this, but some protocols (MQTT) do not
   * setup the transfer correctly, it seems
  if(data->conn->writesockfd == CURL_SOCKET_BAD) {
    failf(data, "transfer not setup for sending");
    DEBUGASSERT(0);
    return CURLE_SEND_ERROR;
  } */
  sockindex = ((data->conn->writesockfd != CURL_SOCKET_BAD) &&
               (data->conn->writesockfd == data->conn->sock[SECONDARYSOCKET]));
  result = Curl_conn_send(data, sockindex, buf, blen, pnwritten);
  if(result == CURLE_AGAIN) {
    result = CURLE_OK;
    *pnwritten = 0;
  }
  else if(!result && *pnwritten)
    data->info.request_size += *pnwritten;

  return result;
}

CURLcode Curl_xfer_recv(struct Curl_easy *data,
                        char *buf, size_t blen,
                        ssize_t *pnrcvd)
{
  int sockindex;

  if(!data || !data->conn)
    return CURLE_FAILED_INIT;
  /* FIXME: would like to enable this, but some protocols (MQTT) do not
   * setup the transfer correctly, it seems
  if(data->conn->sockfd == CURL_SOCKET_BAD) {
    failf(data, "transfer not setup for receiving");
    DEBUGASSERT(0);
    return CURLE_RECV_ERROR;
  } */
  sockindex = ((data->conn->sockfd != CURL_SOCKET_BAD) &&
               (data->conn->sockfd == data->conn->sock[SECONDARYSOCKET]));
  if(data->set.buffer_size > 0 && (size_t)data->set.buffer_size < blen)
    blen = (size_t)data->set.buffer_size;
  return Curl_conn_recv(data, sockindex, buf, blen, pnrcvd);
}

CURLcode Curl_xfer_send_close(struct Curl_easy *data)
{
  Curl_conn_ev_data_done_send(data);
  return CURLE_OK;
}
