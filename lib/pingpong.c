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
 *   'pingpong' is for generic back-and-forth support functions used by FTP,
 *   IMAP, POP3, SMTP and whatever more that likes them.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include "urldata.h"
#include "cfilters.h"
#include "connect.h"
#include "sendf.h"
#include "select.h"
#include "progress.h"
#include "speedcheck.h"
#include "pingpong.h"
#include "multiif.h"
#include "vtls/vtls.h"
#include "strdup.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef USE_PINGPONG

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
timediff_t Curl_pp_state_timeout(struct Curl_easy *data,
                                 struct pingpong *pp, bool disconnecting)
{
  timediff_t timeout_ms; /* in milliseconds */
  timediff_t response_time = (data->set.server_response_timeout) ?
    data->set.server_response_timeout : pp->response_time;
  struct curltime now = curlx_now();

  /* if CURLOPT_SERVER_RESPONSE_TIMEOUT is set, use that to determine
     remaining time, or use pp->response because SERVER_RESPONSE_TIMEOUT is
     supposed to govern the response for any given server response, not for
     the time from connect to the given server response. */

  /* Without a requested timeout, we only wait 'response_time' seconds for the
     full response to arrive before we bail out */
  timeout_ms = response_time - curlx_timediff(now, pp->response);

  if(data->set.timeout && !disconnecting) {
    /* if timeout is requested, find out how much overall remains */
    timediff_t timeout2_ms = Curl_timeleft(data, &now, FALSE);
    /* pick the lowest number */
    timeout_ms = CURLMIN(timeout_ms, timeout2_ms);
  }

  if(disconnecting) {
    timediff_t total_left_ms = Curl_timeleft(data, NULL, FALSE);
    timeout_ms = CURLMIN(timeout_ms, CURLMAX(total_left_ms, 0));
  }

  return timeout_ms;
}

/*
 * Curl_pp_statemach()
 */
CURLcode Curl_pp_statemach(struct Curl_easy *data,
                           struct pingpong *pp, bool block,
                           bool disconnecting)
{
  struct connectdata *conn = data->conn;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  timediff_t interval_ms;
  timediff_t timeout_ms = Curl_pp_state_timeout(data, pp, disconnecting);
  CURLcode result = CURLE_OK;

  if(timeout_ms <= 0) {
    failf(data, "server response timeout");
    return CURLE_OPERATION_TIMEDOUT; /* already too little time */
  }

  DEBUGF(infof(data, "pp_statematch, timeout=%" FMT_TIMEDIFF_T, timeout_ms));
  if(block) {
    interval_ms = 1000;  /* use 1 second timeout intervals */
    if(timeout_ms < interval_ms)
      interval_ms = timeout_ms;
  }
  else
    interval_ms = 0; /* immediate */

  if(Curl_conn_data_pending(data, FIRSTSOCKET))
    rc = 1;
  else if(pp->overflow)
    /* We are receiving and there is data in the cache so just read it */
    rc = 1;
  else if(!pp->sendleft && Curl_conn_data_pending(data, FIRSTSOCKET))
    /* We are receiving and there is data ready in the SSL library */
    rc = 1;
  else
    rc = Curl_socket_check(pp->sendleft ? CURL_SOCKET_BAD : sock, /* reading */
                           CURL_SOCKET_BAD,
                           pp->sendleft ? sock : CURL_SOCKET_BAD, /* writing */
                           interval_ms);

  if(block) {
    /* if we did not wait, we do not have to spend time on this now */
    if(Curl_pgrsUpdate(data))
      result = CURLE_ABORTED_BY_CALLBACK;
    else
      result = Curl_speedcheck(data, curlx_now());

    if(result)
      return result;
  }

  if(rc == -1) {
    failf(data, "select/poll error");
    result = CURLE_OUT_OF_MEMORY;
  }
  else if(rc)
    result = pp->statemachine(data, data->conn);
  else if(disconnecting)
    return CURLE_OPERATION_TIMEDOUT;

  return result;
}

/* initialize stuff to prepare for reading a fresh new response */
void Curl_pp_init(struct pingpong *pp)
{
  DEBUGASSERT(!pp->initialised);
  pp->nread_resp = 0;
  pp->response = curlx_now(); /* start response time-out now! */
  pp->pending_resp = TRUE;
  curlx_dyn_init(&pp->sendbuf, DYN_PINGPPONG_CMD);
  curlx_dyn_init(&pp->recvbuf, DYN_PINGPPONG_CMD);
  pp->initialised = TRUE;
}

/***********************************************************************
 *
 * Curl_pp_vsendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
CURLcode Curl_pp_vsendf(struct Curl_easy *data,
                        struct pingpong *pp,
                        const char *fmt,
                        va_list args)
{
  size_t bytes_written = 0;
  size_t write_len;
  char *s;
  CURLcode result;
  struct connectdata *conn = data->conn;

#ifdef HAVE_GSSAPI
  enum protection_level data_sec;
#endif

  DEBUGASSERT(pp->sendleft == 0);
  DEBUGASSERT(pp->sendsize == 0);
  DEBUGASSERT(pp->sendthis == NULL);

  if(!conn)
    /* cannot send without a connection! */
    return CURLE_SEND_ERROR;

  curlx_dyn_reset(&pp->sendbuf);
  result = curlx_dyn_vaddf(&pp->sendbuf, fmt, args);
  if(result)
    return result;

  /* append CRLF */
  result = curlx_dyn_addn(&pp->sendbuf, "\r\n", 2);
  if(result)
    return result;

  pp->pending_resp = TRUE;
  write_len = curlx_dyn_len(&pp->sendbuf);
  s = curlx_dyn_ptr(&pp->sendbuf);

#ifdef HAVE_GSSAPI
  conn->data_prot = PROT_CMD;
#endif
  result = Curl_conn_send(data, FIRSTSOCKET, s, write_len, FALSE,
                          &bytes_written);
  if(result == CURLE_AGAIN) {
    bytes_written = 0;
  }
  else if(result)
    return result;
#ifdef HAVE_GSSAPI
  data_sec = conn->data_prot;
  DEBUGASSERT(data_sec > PROT_NONE && data_sec < PROT_LAST);
  conn->data_prot = (unsigned char)data_sec;
#endif

  Curl_debug(data, CURLINFO_HEADER_OUT, s, bytes_written);

  if(bytes_written != write_len) {
    /* the whole chunk was not sent, keep it around and adjust sizes */
    pp->sendthis = s;
    pp->sendsize = write_len;
    pp->sendleft = write_len - bytes_written;
  }
  else {
    pp->sendthis = NULL;
    pp->sendleft = pp->sendsize = 0;
    pp->response = curlx_now();
  }

  return CURLE_OK;
}


/***********************************************************************
 *
 * Curl_pp_sendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
CURLcode Curl_pp_sendf(struct Curl_easy *data, struct pingpong *pp,
                       const char *fmt, ...)
{
  CURLcode result;
  va_list ap;
  va_start(ap, fmt);

  result = Curl_pp_vsendf(data, pp, fmt, ap);

  va_end(ap);

  return result;
}

static CURLcode pingpong_read(struct Curl_easy *data,
                              int sockindex,
                              char *buffer,
                              size_t buflen,
                              ssize_t *nread)
{
  CURLcode result;
#ifdef HAVE_GSSAPI
  enum protection_level prot = data->conn->data_prot;
  data->conn->data_prot = PROT_CLEAR;
#endif
  result = Curl_conn_recv(data, sockindex, buffer, buflen, nread);
#ifdef HAVE_GSSAPI
  DEBUGASSERT(prot  > PROT_NONE && prot < PROT_LAST);
  data->conn->data_prot = (unsigned char)prot;
#endif
  return result;
}

/*
 * Curl_pp_readresp()
 *
 * Reads a piece of a server response.
 */
CURLcode Curl_pp_readresp(struct Curl_easy *data,
                          int sockindex,
                          struct pingpong *pp,
                          int *code, /* return the server code if done */
                          size_t *size) /* size of the response */
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  ssize_t gotbytes;
  char buffer[900];

  *code = 0; /* 0 for errors or not done */
  *size = 0;

  do {
    gotbytes = 0;
    if(pp->nfinal) {
      /* a previous call left this many bytes in the beginning of the buffer as
         that was the final line; now ditch that */
      size_t full = curlx_dyn_len(&pp->recvbuf);

      /* trim off the "final" leading part */
      curlx_dyn_tail(&pp->recvbuf, full -  pp->nfinal);

      pp->nfinal = 0; /* now gone */
    }
    if(!pp->overflow) {
      result = pingpong_read(data, sockindex, buffer, sizeof(buffer),
                             &gotbytes);
      if(result == CURLE_AGAIN)
        return CURLE_OK;

      if(result)
        return result;

      if(gotbytes <= 0) {
        failf(data, "response reading failed (errno: %d)", SOCKERRNO);
        return CURLE_RECV_ERROR;
      }

      result = curlx_dyn_addn(&pp->recvbuf, buffer, gotbytes);
      if(result)
        return result;

      data->req.headerbytecount += (unsigned int)gotbytes;

      pp->nread_resp += gotbytes;
    }

    do {
      char *line = curlx_dyn_ptr(&pp->recvbuf);
      char *nl = memchr(line, '\n', curlx_dyn_len(&pp->recvbuf));
      if(nl) {
        /* a newline is CRLF in pp-talk, so the CR is ignored as
           the line is not really terminated until the LF comes */
        size_t length = nl - line + 1;

        /* output debug output if that is requested */
#ifdef HAVE_GSSAPI
        if(!conn->sec_complete)
#endif
          Curl_debug(data, CURLINFO_HEADER_IN, line, length);

        /*
         * Pass all response-lines to the callback function registered for
         * "headers". The response lines can be seen as a kind of headers.
         */
        result = Curl_client_write(data, CLIENTWRITE_INFO, line, length);
        if(result)
          return result;

        if(pp->endofresp(data, conn, line, length, code)) {
          /* When at "end of response", keep the endofresp line first in the
             buffer since it will be accessed outside (by pingpong
             parsers). Store the overflow counter to inform about additional
             data in this buffer after the endofresp line. */
          pp->nfinal = length;
          if(curlx_dyn_len(&pp->recvbuf) > length)
            pp->overflow = curlx_dyn_len(&pp->recvbuf) - length;
          else
            pp->overflow = 0;
          *size = pp->nread_resp; /* size of the response */
          pp->nread_resp = 0; /* restart */
          gotbytes = 0; /* force break out of outer loop */
          break;
        }
        if(curlx_dyn_len(&pp->recvbuf) > length)
          /* keep the remaining piece */
          curlx_dyn_tail((&pp->recvbuf), curlx_dyn_len(&pp->recvbuf) - length);
        else
          curlx_dyn_reset(&pp->recvbuf);
      }
      else {
        /* without a newline, there is no overflow */
        pp->overflow = 0;
        break;
      }

    } while(1); /* while there is buffer left to scan */

  } while(gotbytes == sizeof(buffer));

  pp->pending_resp = FALSE;

  return result;
}

int Curl_pp_getsock(struct Curl_easy *data,
                    struct pingpong *pp, curl_socket_t *socks)
{
  struct connectdata *conn = data->conn;
  socks[0] = conn->sock[FIRSTSOCKET];

  if(pp->sendleft) {
    /* write mode */
    return GETSOCK_WRITESOCK(0);
  }

  /* read mode */
  return GETSOCK_READSOCK(0);
}

bool Curl_pp_needs_flush(struct Curl_easy *data,
                         struct pingpong *pp)
{
  (void)data;
  return pp->sendleft > 0;
}

CURLcode Curl_pp_flushsend(struct Curl_easy *data,
                           struct pingpong *pp)
{
  /* we have a piece of a command still left to send */
  size_t written;
  CURLcode result;

  if(!Curl_pp_needs_flush(data, pp))
    return CURLE_OK;

  result = Curl_conn_send(data, FIRSTSOCKET,
                          pp->sendthis + pp->sendsize - pp->sendleft,
                          pp->sendleft, FALSE, &written);
  if(result == CURLE_AGAIN) {
    result = CURLE_OK;
    written = 0;
  }
  if(result)
    return result;

  if(written != pp->sendleft) {
    /* only a fraction was sent */
    pp->sendleft -= written;
  }
  else {
    pp->sendthis = NULL;
    pp->sendleft = pp->sendsize = 0;
    pp->response = curlx_now();
  }
  return CURLE_OK;
}

CURLcode Curl_pp_disconnect(struct pingpong *pp)
{
  if(pp->initialised) {
    curlx_dyn_free(&pp->sendbuf);
    curlx_dyn_free(&pp->recvbuf);
    memset(pp, 0, sizeof(*pp));
  }
  return CURLE_OK;
}

bool Curl_pp_moredata(struct pingpong *pp)
{
  return !pp->sendleft && curlx_dyn_len(&pp->recvbuf) > pp->nfinal;
}

#endif
