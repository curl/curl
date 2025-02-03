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
 *   'pingpong' is for generic back-and-forth support functions used by FTP,
 *   IMAP, POP3, SMTP and whatever more that likes them.
 *
 ***************************************************************************/

#include "fetch_setup.h"

#include "urldata.h"
#include "cfilters.h"
#include "sendf.h"
#include "select.h"
#include "progress.h"
#include "speedcheck.h"
#include "pingpong.h"
#include "multiif.h"
#include "vtls/vtls.h"
#include "strdup.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

#ifdef USE_PINGPONG

/* Returns timeout in ms. 0 or negative number means the timeout has already
   triggered */
timediff_t Fetch_pp_state_timeout(struct Fetch_easy *data,
                                 struct pingpong *pp, bool disconnecting)
{
  struct connectdata *conn = data->conn;
  timediff_t timeout_ms; /* in milliseconds */
  timediff_t response_time = (data->set.server_response_timeout) ? data->set.server_response_timeout : pp->response_time;

  /* if FETCHOPT_SERVER_RESPONSE_TIMEOUT is set, use that to determine
     remaining time, or use pp->response because SERVER_RESPONSE_TIMEOUT is
     supposed to govern the response for any given server response, not for
     the time from connect to the given server response. */

  /* Without a requested timeout, we only wait 'response_time' seconds for the
     full response to arrive before we bail out */
  timeout_ms = response_time -
               Fetch_timediff(Fetch_now(), pp->response); /* spent time */

  if (data->set.timeout && !disconnecting)
  {
    /* if timeout is requested, find out how much remaining time we have */
    timediff_t timeout2_ms = data->set.timeout -                   /* timeout time */
                             Fetch_timediff(Fetch_now(), conn->now); /* spent time */

    /* pick the lowest number */
    timeout_ms = FETCHMIN(timeout_ms, timeout2_ms);
  }

  return timeout_ms;
}

/*
 * Fetch_pp_statemach()
 */
FETCHcode Fetch_pp_statemach(struct Fetch_easy *data,
                            struct pingpong *pp, bool block,
                            bool disconnecting)
{
  struct connectdata *conn = data->conn;
  fetch_socket_t sock = conn->sock[FIRSTSOCKET];
  int rc;
  timediff_t interval_ms;
  timediff_t timeout_ms = Fetch_pp_state_timeout(data, pp, disconnecting);
  FETCHcode result = FETCHE_OK;

  if (timeout_ms <= 0)
  {
    failf(data, "server response timeout");
    return FETCHE_OPERATION_TIMEDOUT; /* already too little time */
  }

  if (block)
  {
    interval_ms = 1000; /* use 1 second timeout intervals */
    if (timeout_ms < interval_ms)
      interval_ms = timeout_ms;
  }
  else
    interval_ms = 0; /* immediate */

  if (Fetch_conn_data_pending(data, FIRSTSOCKET))
    rc = 1;
  else if (pp->overflow)
    /* We are receiving and there is data in the cache so just read it */
    rc = 1;
  else if (!pp->sendleft && Fetch_conn_data_pending(data, FIRSTSOCKET))
    /* We are receiving and there is data ready in the SSL library */
    rc = 1;
  else
    rc = Fetch_socket_check(pp->sendleft ? FETCH_SOCKET_BAD : sock, /* reading */
                           FETCH_SOCKET_BAD,
                           pp->sendleft ? sock : FETCH_SOCKET_BAD, /* writing */
                           interval_ms);

  if (block)
  {
    /* if we did not wait, we do not have to spend time on this now */
    if (Fetch_pgrsUpdate(data))
      result = FETCHE_ABORTED_BY_CALLBACK;
    else
      result = Fetch_speedcheck(data, Fetch_now());

    if (result)
      return result;
  }

  if (rc == -1)
  {
    failf(data, "select/poll error");
    result = FETCHE_OUT_OF_MEMORY;
  }
  else if (rc)
    result = pp->statemachine(data, data->conn);

  return result;
}

/* initialize stuff to prepare for reading a fresh new response */
void Fetch_pp_init(struct pingpong *pp)
{
  pp->nread_resp = 0;
  pp->response = Fetch_now(); /* start response time-out now! */
  pp->pending_resp = TRUE;
  Fetch_dyn_init(&pp->sendbuf, DYN_PINGPPONG_CMD);
  Fetch_dyn_init(&pp->recvbuf, DYN_PINGPPONG_CMD);
}

/***********************************************************************
 *
 * Fetch_pp_vsendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
FETCHcode Fetch_pp_vsendf(struct Fetch_easy *data,
                         struct pingpong *pp,
                         const char *fmt,
                         va_list args)
{
  size_t bytes_written = 0;
  size_t write_len;
  char *s;
  FETCHcode result;
  struct connectdata *conn = data->conn;

#ifdef HAVE_GSSAPI
  enum protection_level data_sec;
#endif

  DEBUGASSERT(pp->sendleft == 0);
  DEBUGASSERT(pp->sendsize == 0);
  DEBUGASSERT(pp->sendthis == NULL);

  if (!conn)
    /* cannot send without a connection! */
    return FETCHE_SEND_ERROR;

  Fetch_dyn_reset(&pp->sendbuf);
  result = Fetch_dyn_vaddf(&pp->sendbuf, fmt, args);
  if (result)
    return result;

  /* append CRLF */
  result = Fetch_dyn_addn(&pp->sendbuf, "\r\n", 2);
  if (result)
    return result;

  pp->pending_resp = TRUE;
  write_len = Fetch_dyn_len(&pp->sendbuf);
  s = Fetch_dyn_ptr(&pp->sendbuf);

#ifdef HAVE_GSSAPI
  conn->data_prot = PROT_CMD;
#endif
  result = Fetch_conn_send(data, FIRSTSOCKET, s, write_len, FALSE,
                          &bytes_written);
  if (result == FETCHE_AGAIN)
  {
    bytes_written = 0;
  }
  else if (result)
    return result;
#ifdef HAVE_GSSAPI
  data_sec = conn->data_prot;
  DEBUGASSERT(data_sec > PROT_NONE && data_sec < PROT_LAST);
  conn->data_prot = (unsigned char)data_sec;
#endif

  Fetch_debug(data, FETCHINFO_HEADER_OUT, s, bytes_written);

  if (bytes_written != write_len)
  {
    /* the whole chunk was not sent, keep it around and adjust sizes */
    pp->sendthis = s;
    pp->sendsize = write_len;
    pp->sendleft = write_len - bytes_written;
  }
  else
  {
    pp->sendthis = NULL;
    pp->sendleft = pp->sendsize = 0;
    pp->response = Fetch_now();
  }

  return FETCHE_OK;
}

/***********************************************************************
 *
 * Fetch_pp_sendf()
 *
 * Send the formatted string as a command to a pingpong server. Note that
 * the string should not have any CRLF appended, as this function will
 * append the necessary things itself.
 *
 * made to never block
 */
FETCHcode Fetch_pp_sendf(struct Fetch_easy *data, struct pingpong *pp,
                        const char *fmt, ...)
{
  FETCHcode result;
  va_list ap;
  va_start(ap, fmt);

  result = Fetch_pp_vsendf(data, pp, fmt, ap);

  va_end(ap);

  return result;
}

static FETCHcode pingpong_read(struct Fetch_easy *data,
                               int sockindex,
                               char *buffer,
                               size_t buflen,
                               ssize_t *nread)
{
  FETCHcode result;
#ifdef HAVE_GSSAPI
  enum protection_level prot = data->conn->data_prot;
  data->conn->data_prot = PROT_CLEAR;
#endif
  result = Fetch_conn_recv(data, sockindex, buffer, buflen, nread);
#ifdef HAVE_GSSAPI
  DEBUGASSERT(prot > PROT_NONE && prot < PROT_LAST);
  data->conn->data_prot = (unsigned char)prot;
#endif
  return result;
}

/*
 * Fetch_pp_readresp()
 *
 * Reads a piece of a server response.
 */
FETCHcode Fetch_pp_readresp(struct Fetch_easy *data,
                           int sockindex,
                           struct pingpong *pp,
                           int *code,    /* return the server code if done */
                           size_t *size) /* size of the response */
{
  struct connectdata *conn = data->conn;
  FETCHcode result = FETCHE_OK;
  ssize_t gotbytes;
  char buffer[900];

  *code = 0; /* 0 for errors or not done */
  *size = 0;

  do
  {
    gotbytes = 0;
    if (pp->nfinal)
    {
      /* a previous call left this many bytes in the beginning of the buffer as
         that was the final line; now ditch that */
      size_t full = Fetch_dyn_len(&pp->recvbuf);

      /* trim off the "final" leading part */
      Fetch_dyn_tail(&pp->recvbuf, full - pp->nfinal);

      pp->nfinal = 0; /* now gone */
    }
    if (!pp->overflow)
    {
      result = pingpong_read(data, sockindex, buffer, sizeof(buffer),
                             &gotbytes);
      if (result == FETCHE_AGAIN)
        return FETCHE_OK;

      if (result)
        return result;

      if (gotbytes <= 0)
      {
        failf(data, "response reading failed (errno: %d)", SOCKERRNO);
        return FETCHE_RECV_ERROR;
      }

      result = Fetch_dyn_addn(&pp->recvbuf, buffer, gotbytes);
      if (result)
        return result;

      data->req.headerbytecount += (unsigned int)gotbytes;

      pp->nread_resp += gotbytes;
    }

    do
    {
      char *line = Fetch_dyn_ptr(&pp->recvbuf);
      char *nl = memchr(line, '\n', Fetch_dyn_len(&pp->recvbuf));
      if (nl)
      {
        /* a newline is CRLF in pp-talk, so the CR is ignored as
           the line is not really terminated until the LF comes */
        size_t length = nl - line + 1;

        /* output debug output if that is requested */
#ifdef HAVE_GSSAPI
        if (!conn->sec_complete)
#endif
          Fetch_debug(data, FETCHINFO_HEADER_IN, line, length);

        /*
         * Pass all response-lines to the callback function registered for
         * "headers". The response lines can be seen as a kind of headers.
         */
        result = Fetch_client_write(data, CLIENTWRITE_INFO, line, length);
        if (result)
          return result;

        if (pp->endofresp(data, conn, line, length, code))
        {
          /* When at "end of response", keep the endofresp line first in the
             buffer since it will be accessed outside (by pingpong
             parsers). Store the overflow counter to inform about additional
             data in this buffer after the endofresp line. */
          pp->nfinal = length;
          if (Fetch_dyn_len(&pp->recvbuf) > length)
            pp->overflow = Fetch_dyn_len(&pp->recvbuf) - length;
          else
            pp->overflow = 0;
          *size = pp->nread_resp; /* size of the response */
          pp->nread_resp = 0;     /* restart */
          gotbytes = 0;           /* force break out of outer loop */
          break;
        }
        if (Fetch_dyn_len(&pp->recvbuf) > length)
          /* keep the remaining piece */
          Fetch_dyn_tail((&pp->recvbuf), Fetch_dyn_len(&pp->recvbuf) - length);
        else
          Fetch_dyn_reset(&pp->recvbuf);
      }
      else
      {
        /* without a newline, there is no overflow */
        pp->overflow = 0;
        break;
      }

    } while (1); /* while there is buffer left to scan */

  } while (gotbytes == sizeof(buffer));

  pp->pending_resp = FALSE;

  return result;
}

int Fetch_pp_getsock(struct Fetch_easy *data,
                    struct pingpong *pp, fetch_socket_t *socks)
{
  struct connectdata *conn = data->conn;
  socks[0] = conn->sock[FIRSTSOCKET];

  if (pp->sendleft)
  {
    /* write mode */
    return GETSOCK_WRITESOCK(0);
  }

  /* read mode */
  return GETSOCK_READSOCK(0);
}

bool Fetch_pp_needs_flush(struct Fetch_easy *data,
                         struct pingpong *pp)
{
  (void)data;
  return pp->sendleft > 0;
}

FETCHcode Fetch_pp_flushsend(struct Fetch_easy *data,
                            struct pingpong *pp)
{
  /* we have a piece of a command still left to send */
  size_t written;
  FETCHcode result;

  if (!Fetch_pp_needs_flush(data, pp))
    return FETCHE_OK;

  result = Fetch_conn_send(data, FIRSTSOCKET,
                          pp->sendthis + pp->sendsize - pp->sendleft,
                          pp->sendleft, FALSE, &written);
  if (result == FETCHE_AGAIN)
  {
    result = FETCHE_OK;
    written = 0;
  }
  if (result)
    return result;

  if (written != pp->sendleft)
  {
    /* only a fraction was sent */
    pp->sendleft -= written;
  }
  else
  {
    pp->sendthis = NULL;
    pp->sendleft = pp->sendsize = 0;
    pp->response = Fetch_now();
  }
  return FETCHE_OK;
}

FETCHcode Fetch_pp_disconnect(struct pingpong *pp)
{
  Fetch_dyn_free(&pp->sendbuf);
  Fetch_dyn_free(&pp->recvbuf);
  return FETCHE_OK;
}

bool Fetch_pp_moredata(struct pingpong *pp)
{
  return !pp->sendleft && Fetch_dyn_len(&pp->recvbuf) > pp->nfinal;
}

#endif
