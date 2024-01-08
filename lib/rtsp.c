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

#if !defined(CURL_DISABLE_RTSP) && !defined(USE_HYPER)

#include "urldata.h"
#include <curl/curl.h>
#include "transfer.h"
#include "sendf.h"
#include "multiif.h"
#include "http.h"
#include "url.h"
#include "progress.h"
#include "rtsp.h"
#include "strcase.h"
#include "select.h"
#include "connect.h"
#include "cfilters.h"
#include "strdup.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define RTP_PKT_LENGTH(p) ((((unsigned int)((unsigned char)((p)[2]))) << 8) | \
                            ((unsigned int)((unsigned char)((p)[3]))))

/* protocol-specific functions set up to be called by the main engine */
static CURLcode rtsp_do(struct Curl_easy *data, bool *done);
static CURLcode rtsp_done(struct Curl_easy *data, CURLcode, bool premature);
static CURLcode rtsp_connect(struct Curl_easy *data, bool *done);
static CURLcode rtsp_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead);
static int rtsp_getsock_do(struct Curl_easy *data,
                           struct connectdata *conn, curl_socket_t *socks);

/*
 * Parse and write out any available RTP data.
 * @param data     the transfer
 * @param conn     the connection
 * @param buf      data read from connection
 * @param blen     amount of data in buf
 * @param consumed out, number of blen consumed
 * @param readmore out, TRUE iff complete buf was consumed and more data
 *                 is needed
 */
static CURLcode rtsp_rtp_readwrite(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   const char *buf,
                                   size_t blen,
                                   size_t *pconsumed,
                                   bool *readmore);

static CURLcode rtsp_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn);
static unsigned int rtsp_conncheck(struct Curl_easy *data,
                                   struct connectdata *check,
                                   unsigned int checks_to_perform);

/* this returns the socket to wait for in the DO and DOING state for the multi
   interface and then we're always _sending_ a request and thus we wait for
   the single socket to become writable only */
static int rtsp_getsock_do(struct Curl_easy *data, struct connectdata *conn,
                           curl_socket_t *socks)
{
  /* write mode */
  (void)data;
  socks[0] = conn->sock[FIRSTSOCKET];
  return GETSOCK_WRITESOCK(0);
}

static
CURLcode rtp_client_write(struct Curl_easy *data, const char *ptr, size_t len);
static
CURLcode rtsp_parse_transport(struct Curl_easy *data, char *transport);


/*
 * RTSP handler interface.
 */
const struct Curl_handler Curl_handler_rtsp = {
  "RTSP",                               /* scheme */
  rtsp_setup_connection,                /* setup_connection */
  rtsp_do,                              /* do_it */
  rtsp_done,                            /* done */
  ZERO_NULL,                            /* do_more */
  rtsp_connect,                         /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  rtsp_getsock_do,                      /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  rtsp_disconnect,                      /* disconnect */
  rtsp_rtp_readwrite,                   /* readwrite */
  rtsp_conncheck,                       /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_RTSP,                            /* defport */
  CURLPROTO_RTSP,                       /* protocol */
  CURLPROTO_RTSP,                       /* family */
  PROTOPT_NONE                          /* flags */
};

#define MAX_RTP_BUFFERSIZE 1000000 /* arbitrary */

static CURLcode rtsp_setup_connection(struct Curl_easy *data,
                                      struct connectdata *conn)
{
  struct RTSP *rtsp;
  (void)conn;

  data->req.p.rtsp = rtsp = calloc(1, sizeof(struct RTSP));
  if(!rtsp)
    return CURLE_OUT_OF_MEMORY;

  Curl_dyn_init(&conn->proto.rtspc.buf, MAX_RTP_BUFFERSIZE);
  return CURLE_OK;
}


/*
 * Function to check on various aspects of a connection.
 */
static unsigned int rtsp_conncheck(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform)
{
  unsigned int ret_val = CONNRESULT_NONE;
  (void)data;

  if(checks_to_perform & CONNCHECK_ISDEAD) {
    bool input_pending;
    if(!Curl_conn_is_alive(data, conn, &input_pending))
      ret_val |= CONNRESULT_DEAD;
  }

  return ret_val;
}


static CURLcode rtsp_connect(struct Curl_easy *data, bool *done)
{
  CURLcode httpStatus;

  httpStatus = Curl_http_connect(data, done);

  /* Initialize the CSeq if not already done */
  if(data->state.rtsp_next_client_CSeq == 0)
    data->state.rtsp_next_client_CSeq = 1;
  if(data->state.rtsp_next_server_CSeq == 0)
    data->state.rtsp_next_server_CSeq = 1;

  data->conn->proto.rtspc.rtp_channel = -1;

  return httpStatus;
}

static CURLcode rtsp_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead)
{
  (void) dead;
  (void) data;
  Curl_dyn_free(&conn->proto.rtspc.buf);
  return CURLE_OK;
}


static CURLcode rtsp_done(struct Curl_easy *data,
                          CURLcode status, bool premature)
{
  struct RTSP *rtsp = data->req.p.rtsp;
  CURLcode httpStatus;

  /* Bypass HTTP empty-reply checks on receive */
  if(data->set.rtspreq == RTSPREQ_RECEIVE)
    premature = TRUE;

  httpStatus = Curl_http_done(data, status, premature);

  if(rtsp && !status && !httpStatus) {
    /* Check the sequence numbers */
    long CSeq_sent = rtsp->CSeq_sent;
    long CSeq_recv = rtsp->CSeq_recv;
    if((data->set.rtspreq != RTSPREQ_RECEIVE) && (CSeq_sent != CSeq_recv)) {
      failf(data,
            "The CSeq of this request %ld did not match the response %ld",
            CSeq_sent, CSeq_recv);
      return CURLE_RTSP_CSEQ_ERROR;
    }
    if(data->set.rtspreq == RTSPREQ_RECEIVE &&
       (data->conn->proto.rtspc.rtp_channel == -1)) {
      infof(data, "Got an RTP Receive with a CSeq of %ld", CSeq_recv);
    }
  }

  return httpStatus;
}

static CURLcode rtsp_do(struct Curl_easy *data, bool *done)
{
  struct connectdata *conn = data->conn;
  CURLcode result = CURLE_OK;
  Curl_RtspReq rtspreq = data->set.rtspreq;
  struct RTSP *rtsp = data->req.p.rtsp;
  struct dynbuf req_buffer;
  curl_off_t postsize = 0; /* for ANNOUNCE and SET_PARAMETER */
  curl_off_t putsize = 0; /* for ANNOUNCE and SET_PARAMETER */

  const char *p_request = NULL;
  const char *p_session_id = NULL;
  const char *p_accept = NULL;
  const char *p_accept_encoding = NULL;
  const char *p_range = NULL;
  const char *p_referrer = NULL;
  const char *p_stream_uri = NULL;
  const char *p_transport = NULL;
  const char *p_uagent = NULL;
  const char *p_proxyuserpwd = NULL;
  const char *p_userpwd = NULL;

  *done = TRUE;

  rtsp->CSeq_sent = data->state.rtsp_next_client_CSeq;
  rtsp->CSeq_recv = 0;

  /* Setup the first_* fields to allow auth details get sent
     to this origin */

  if(!data->state.first_host) {
    data->state.first_host = strdup(conn->host.name);
    if(!data->state.first_host)
      return CURLE_OUT_OF_MEMORY;

    data->state.first_remote_port = conn->remote_port;
    data->state.first_remote_protocol = conn->handler->protocol;
  }

  /* Setup the 'p_request' pointer to the proper p_request string
   * Since all RTSP requests are included here, there is no need to
   * support custom requests like HTTP.
   **/
  data->req.no_body = TRUE; /* most requests don't contain a body */
  switch(rtspreq) {
  default:
    failf(data, "Got invalid RTSP request");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case RTSPREQ_OPTIONS:
    p_request = "OPTIONS";
    break;
  case RTSPREQ_DESCRIBE:
    p_request = "DESCRIBE";
    data->req.no_body = FALSE;
    break;
  case RTSPREQ_ANNOUNCE:
    p_request = "ANNOUNCE";
    break;
  case RTSPREQ_SETUP:
    p_request = "SETUP";
    break;
  case RTSPREQ_PLAY:
    p_request = "PLAY";
    break;
  case RTSPREQ_PAUSE:
    p_request = "PAUSE";
    break;
  case RTSPREQ_TEARDOWN:
    p_request = "TEARDOWN";
    break;
  case RTSPREQ_GET_PARAMETER:
    /* GET_PARAMETER's no_body status is determined later */
    p_request = "GET_PARAMETER";
    data->req.no_body = FALSE;
    break;
  case RTSPREQ_SET_PARAMETER:
    p_request = "SET_PARAMETER";
    break;
  case RTSPREQ_RECORD:
    p_request = "RECORD";
    break;
  case RTSPREQ_RECEIVE:
    p_request = "";
    /* Treat interleaved RTP as body */
    data->req.no_body = FALSE;
    break;
  case RTSPREQ_LAST:
    failf(data, "Got invalid RTSP request: RTSPREQ_LAST");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(rtspreq == RTSPREQ_RECEIVE) {
    Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);

    return result;
  }

  p_session_id = data->set.str[STRING_RTSP_SESSION_ID];
  if(!p_session_id &&
     (rtspreq & ~(RTSPREQ_OPTIONS | RTSPREQ_DESCRIBE | RTSPREQ_SETUP))) {
    failf(data, "Refusing to issue an RTSP request [%s] without a session ID.",
          p_request);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  /* Stream URI. Default to server '*' if not specified */
  if(data->set.str[STRING_RTSP_STREAM_URI]) {
    p_stream_uri = data->set.str[STRING_RTSP_STREAM_URI];
  }
  else {
    p_stream_uri = "*";
  }

  /* Transport Header for SETUP requests */
  p_transport = Curl_checkheaders(data, STRCONST("Transport"));
  if(rtspreq == RTSPREQ_SETUP && !p_transport) {
    /* New Transport: setting? */
    if(data->set.str[STRING_RTSP_TRANSPORT]) {
      Curl_safefree(data->state.aptr.rtsp_transport);

      data->state.aptr.rtsp_transport =
        aprintf("Transport: %s\r\n",
                data->set.str[STRING_RTSP_TRANSPORT]);
      if(!data->state.aptr.rtsp_transport)
        return CURLE_OUT_OF_MEMORY;
    }
    else {
      failf(data,
            "Refusing to issue an RTSP SETUP without a Transport: header.");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }

    p_transport = data->state.aptr.rtsp_transport;
  }

  /* Accept Headers for DESCRIBE requests */
  if(rtspreq == RTSPREQ_DESCRIBE) {
    /* Accept Header */
    p_accept = Curl_checkheaders(data, STRCONST("Accept"))?
      NULL:"Accept: application/sdp\r\n";

    /* Accept-Encoding header */
    if(!Curl_checkheaders(data, STRCONST("Accept-Encoding")) &&
       data->set.str[STRING_ENCODING]) {
      Curl_safefree(data->state.aptr.accept_encoding);
      data->state.aptr.accept_encoding =
        aprintf("Accept-Encoding: %s\r\n", data->set.str[STRING_ENCODING]);

      if(!data->state.aptr.accept_encoding)
        return CURLE_OUT_OF_MEMORY;

      p_accept_encoding = data->state.aptr.accept_encoding;
    }
  }

  /* The User-Agent string might have been allocated in url.c already, because
     it might have been used in the proxy connect, but if we have got a header
     with the user-agent string specified, we erase the previously made string
     here. */
  if(Curl_checkheaders(data, STRCONST("User-Agent")) &&
     data->state.aptr.uagent) {
    Curl_safefree(data->state.aptr.uagent);
  }
  else if(!Curl_checkheaders(data, STRCONST("User-Agent")) &&
          data->set.str[STRING_USERAGENT]) {
    p_uagent = data->state.aptr.uagent;
  }

  /* setup the authentication headers */
  result = Curl_http_output_auth(data, conn, p_request, HTTPREQ_GET,
                                 p_stream_uri, FALSE);
  if(result)
    return result;

  p_proxyuserpwd = data->state.aptr.proxyuserpwd;
  p_userpwd = data->state.aptr.userpwd;

  /* Referrer */
  Curl_safefree(data->state.aptr.ref);
  if(data->state.referer && !Curl_checkheaders(data, STRCONST("Referer")))
    data->state.aptr.ref = aprintf("Referer: %s\r\n", data->state.referer);

  p_referrer = data->state.aptr.ref;

  /*
   * Range Header
   * Only applies to PLAY, PAUSE, RECORD
   *
   * Go ahead and use the Range stuff supplied for HTTP
   */
  if(data->state.use_range &&
     (rtspreq  & (RTSPREQ_PLAY | RTSPREQ_PAUSE | RTSPREQ_RECORD))) {

    /* Check to see if there is a range set in the custom headers */
    if(!Curl_checkheaders(data, STRCONST("Range")) && data->state.range) {
      Curl_safefree(data->state.aptr.rangeline);
      data->state.aptr.rangeline = aprintf("Range: %s\r\n", data->state.range);
      p_range = data->state.aptr.rangeline;
    }
  }

  /*
   * Sanity check the custom headers
   */
  if(Curl_checkheaders(data, STRCONST("CSeq"))) {
    failf(data, "CSeq cannot be set as a custom header.");
    return CURLE_RTSP_CSEQ_ERROR;
  }
  if(Curl_checkheaders(data, STRCONST("Session"))) {
    failf(data, "Session ID cannot be set as a custom header.");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  /* Initialize a dynamic send buffer */
  Curl_dyn_init(&req_buffer, DYN_RTSP_REQ_HEADER);

  result =
    Curl_dyn_addf(&req_buffer,
                  "%s %s RTSP/1.0\r\n" /* Request Stream-URI RTSP/1.0 */
                  "CSeq: %ld\r\n", /* CSeq */
                  p_request, p_stream_uri, rtsp->CSeq_sent);
  if(result)
    return result;

  /*
   * Rather than do a normal alloc line, keep the session_id unformatted
   * to make comparison easier
   */
  if(p_session_id) {
    result = Curl_dyn_addf(&req_buffer, "Session: %s\r\n", p_session_id);
    if(result)
      return result;
  }

  /*
   * Shared HTTP-like options
   */
  result = Curl_dyn_addf(&req_buffer,
                         "%s" /* transport */
                         "%s" /* accept */
                         "%s" /* accept-encoding */
                         "%s" /* range */
                         "%s" /* referrer */
                         "%s" /* user-agent */
                         "%s" /* proxyuserpwd */
                         "%s" /* userpwd */
                         ,
                         p_transport ? p_transport : "",
                         p_accept ? p_accept : "",
                         p_accept_encoding ? p_accept_encoding : "",
                         p_range ? p_range : "",
                         p_referrer ? p_referrer : "",
                         p_uagent ? p_uagent : "",
                         p_proxyuserpwd ? p_proxyuserpwd : "",
                         p_userpwd ? p_userpwd : "");

  /*
   * Free userpwd now --- cannot reuse this for Negotiate and possibly NTLM
   * with basic and digest, it will be freed anyway by the next request
   */
  Curl_safefree(data->state.aptr.userpwd);

  if(result)
    return result;

  if((rtspreq == RTSPREQ_SETUP) || (rtspreq == RTSPREQ_DESCRIBE)) {
    result = Curl_add_timecondition(data, &req_buffer);
    if(result)
      return result;
  }

  result = Curl_add_custom_headers(data, FALSE, &req_buffer);
  if(result)
    return result;

  if(rtspreq == RTSPREQ_ANNOUNCE ||
     rtspreq == RTSPREQ_SET_PARAMETER ||
     rtspreq == RTSPREQ_GET_PARAMETER) {

    if(data->state.upload) {
      putsize = data->state.infilesize;
      data->state.httpreq = HTTPREQ_PUT;

    }
    else {
      postsize = (data->state.infilesize != -1)?
        data->state.infilesize:
        (data->set.postfields? (curl_off_t)strlen(data->set.postfields):0);
      data->state.httpreq = HTTPREQ_POST;
    }

    if(putsize > 0 || postsize > 0) {
      /* As stated in the http comments, it is probably not wise to
       * actually set a custom Content-Length in the headers */
      if(!Curl_checkheaders(data, STRCONST("Content-Length"))) {
        result =
          Curl_dyn_addf(&req_buffer,
                        "Content-Length: %" CURL_FORMAT_CURL_OFF_T"\r\n",
                        (data->state.upload ? putsize : postsize));
        if(result)
          return result;
      }

      if(rtspreq == RTSPREQ_SET_PARAMETER ||
         rtspreq == RTSPREQ_GET_PARAMETER) {
        if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
          result = Curl_dyn_addn(&req_buffer,
                                 STRCONST("Content-Type: "
                                          "text/parameters\r\n"));
          if(result)
            return result;
        }
      }

      if(rtspreq == RTSPREQ_ANNOUNCE) {
        if(!Curl_checkheaders(data, STRCONST("Content-Type"))) {
          result = Curl_dyn_addn(&req_buffer,
                                 STRCONST("Content-Type: "
                                          "application/sdp\r\n"));
          if(result)
            return result;
        }
      }

      data->state.expect100header = FALSE; /* RTSP posts are simple/small */
    }
    else if(rtspreq == RTSPREQ_GET_PARAMETER) {
      /* Check for an empty GET_PARAMETER (heartbeat) request */
      data->state.httpreq = HTTPREQ_HEAD;
      data->req.no_body = TRUE;
    }
  }

  /* RTSP never allows chunked transfer */
  data->req.forbidchunk = TRUE;
  /* Finish the request buffer */
  result = Curl_dyn_addn(&req_buffer, STRCONST("\r\n"));
  if(result)
    return result;

  if(postsize > 0) {
    result = Curl_dyn_addn(&req_buffer, data->set.postfields,
                           (size_t)postsize);
    if(result)
      return result;
  }

  /* issue the request */
  result = Curl_buffer_send(&req_buffer, data, data->req.p.http,
                            &data->info.request_size, 0, FIRSTSOCKET);
  if(result) {
    failf(data, "Failed sending RTSP request");
    return result;
  }

  Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, putsize?FIRSTSOCKET:-1);

  /* Increment the CSeq on success */
  data->state.rtsp_next_client_CSeq++;

  if(data->req.writebytecount) {
    /* if a request-body has been sent off, we make sure this progress is
       noted properly */
    Curl_pgrsSetUploadCounter(data, data->req.writebytecount);
    if(Curl_pgrsUpdate(data))
      result = CURLE_ABORTED_BY_CALLBACK;
  }

  return result;
}

static CURLcode rtsp_filter_rtp(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     const char *buf,
                                     size_t blen,
                                     bool in_body,
                                     size_t *pconsumed)
{
  struct rtsp_conn *rtspc = &(conn->proto.rtspc);
  CURLcode result = CURLE_OK;

  *pconsumed = 0;
  while(blen) {
    switch(rtspc->state) {

    case RTP_PARSE_SKIP: {
      DEBUGASSERT(Curl_dyn_len(&rtspc->buf) == 0);
      if(in_body && buf[0] != '$') {
        /* in BODY and no valid start, do not consume and return */
        goto out;
      }
      while(blen && buf[0] != '$') {
        if(!in_body && buf[0] == 'R' &&
           data->set.rtspreq != RTSPREQ_RECEIVE) {
          if(strncmp(buf, "RTSP/", (blen < 5) ? blen : 5) == 0) {
            /* This could be the next response, no consume and return */
            if(*pconsumed) {
              DEBUGF(infof(data, "RTP rtsp_filter_rtp[SKIP] RTSP/ prefix, "
                           "skipping %zd bytes of junk", *pconsumed));
            }
            rtspc->state = RTP_PARSE_SKIP;
            rtspc->in_header = TRUE;
            goto out;
          }
        }
        /* junk, consume without buffering */
        *pconsumed += 1;
        ++buf;
        --blen;
      }
      if(blen && buf[0] == '$') {
        /* possible start of an RTP message, buffer */
        if(Curl_dyn_addn(&rtspc->buf, buf, 1)) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }
        *pconsumed += 1;
        ++buf;
        --blen;
        rtspc->state = RTP_PARSE_CHANNEL;
      }
      break;
    }

    case RTP_PARSE_CHANNEL: {
      int idx = ((unsigned char)buf[0]) / 8;
      int off = ((unsigned char)buf[0]) % 8;
      DEBUGASSERT(Curl_dyn_len(&rtspc->buf) == 1);
      if(!(data->state.rtp_channel_mask[idx] & (1 << off))) {
        /* invalid channel number, junk or BODY data */
        rtspc->state = RTP_PARSE_SKIP;
        if(in_body) {
          /* we do not consume this byte, it is BODY data */
          DEBUGF(infof(data, "RTSP: invalid RTP channel %d in BODY, "
                       "treating as BODY data", idx));
          if(*pconsumed == 0) {
            /* We did not consume the initial '$' in our buffer, but had
             * it from an earlier call. We cannot un-consume it and have
             * to write it directly as BODY data */
            result = Curl_client_write(data, CLIENTWRITE_BODY,
                                       Curl_dyn_ptr(&rtspc->buf), 1);
            Curl_dyn_free(&rtspc->buf);
            if(result)
              goto out;
          }
          else {
            /* un-consume the '$' and leave */
            Curl_dyn_free(&rtspc->buf);
            *pconsumed -= 1;
            --buf;
            ++blen;
            goto out;
          }
        }
        else {
          /* not BODY, forget the junk '$'. Do not consume this byte,
           * it might be a start */
          infof(data, "RTSP: invalid RTP channel %d, skipping", idx);
          Curl_dyn_free(&rtspc->buf);
        }
        break;
      }
      /* a valid channel, so we expect this to be a real RTP message */
      rtspc->rtp_channel = (unsigned char)buf[0];
      if(Curl_dyn_addn(&rtspc->buf, buf, 1)) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      *pconsumed += 1;
      ++buf;
      --blen;
      rtspc->state = RTP_PARSE_LEN;
      break;
    }

    case RTP_PARSE_LEN: {
      size_t rtp_len = Curl_dyn_len(&rtspc->buf);
      const char *rtp_buf;
      DEBUGASSERT(rtp_len >= 2 && rtp_len < 4);
      if(Curl_dyn_addn(&rtspc->buf, buf, 1)) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      *pconsumed += 1;
      ++buf;
      --blen;
      if(rtp_len == 2)
        break;
      rtp_buf = Curl_dyn_ptr(&rtspc->buf);
      rtspc->rtp_len = RTP_PKT_LENGTH(rtp_buf) + 4;
      rtspc->state = RTP_PARSE_DATA;
      break;
    }

    case RTP_PARSE_DATA: {
      size_t rtp_len = Curl_dyn_len(&rtspc->buf);
      size_t needed;
      DEBUGASSERT(rtp_len < rtspc->rtp_len);
      needed = rtspc->rtp_len - rtp_len;
      if(needed <= blen) {
        if(Curl_dyn_addn(&rtspc->buf, buf, needed)) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }
        *pconsumed += needed;
        buf += needed;
        blen -= needed;
        /* complete RTP message in buffer */
        DEBUGF(infof(data, "RTP write channel %d rtp_len %zu",
                     rtspc->rtp_channel, rtspc->rtp_len));
        result = rtp_client_write(data, Curl_dyn_ptr(&rtspc->buf),
                                  rtspc->rtp_len);
        Curl_dyn_free(&rtspc->buf);
        rtspc->state = RTP_PARSE_SKIP;
        if(result)
          goto out;
      }
      else {
        if(Curl_dyn_addn(&rtspc->buf, buf, blen)) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }
        *pconsumed += blen;
        buf += blen;
        blen = 0;
      }
      break;
    }

    default:
      DEBUGASSERT(0);
      return CURLE_RECV_ERROR;
    }
  }
out:
  return result;
}

static CURLcode rtsp_rtp_readwrite(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   const char *buf,
                                   size_t blen,
                                   size_t *pconsumed,
                                   bool *readmore)
{
  struct rtsp_conn *rtspc = &(conn->proto.rtspc);
  CURLcode result = CURLE_OK;
  size_t consumed = 0;
  bool in_body;

  if(!data->req.header)
    rtspc->in_header = FALSE;
  in_body = (data->req.headerline && !rtspc->in_header) &&
            (data->req.size >= 0) &&
            (data->req.bytecount < data->req.size);

  *readmore = FALSE;
  *pconsumed = 0;
  if(!blen) {
    goto out;
  }

  /* If header parsing is not onging, extract RTP messages */
  if(!rtspc->in_header) {
    result = rtsp_filter_rtp(data, conn, buf, blen, in_body, &consumed);
    if(result)
      goto out;
    *pconsumed += consumed;
    buf += consumed;
    blen -= consumed;
  }

  /* we want to parse headers, do so */
  if(data->req.header && blen) {
    rtspc->in_header = TRUE;
    result = Curl_http_readwrite_headers(data, conn, buf, blen,
                                         &consumed);
    if(result)
      goto out;

    *pconsumed += consumed;
    buf += consumed;
    blen -= consumed;

    if(!data->req.header)
      rtspc->in_header = FALSE;

    if(!rtspc->in_header) {
      /* If header parsing is done and data left, extract RTP messages */
      in_body = (data->req.headerline && !rtspc->in_header) &&
                (data->req.size >= 0) &&
                (data->req.bytecount < data->req.size);
      result = rtsp_filter_rtp(data, conn, buf, blen, in_body, &consumed);
      if(result)
        goto out;
      *pconsumed += consumed;
    }
  }

  if(rtspc->state != RTP_PARSE_SKIP)
    *readmore = TRUE;

out:
  if(!*readmore && data->set.rtspreq == RTSPREQ_RECEIVE) {
    /* In special mode RECEIVE, we just process one chunk of network
     * data, so we stop the transfer here, if we have no incomplete
     * RTP message pending. */
    data->req.keepon &= ~KEEP_RECV;
  }
  return result;
}

static
CURLcode rtp_client_write(struct Curl_easy *data, const char *ptr, size_t len)
{
  size_t wrote;
  curl_write_callback writeit;
  void *user_ptr;

  if(len == 0) {
    failf(data, "Cannot write a 0 size RTP packet.");
    return CURLE_WRITE_ERROR;
  }

  /* If the user has configured CURLOPT_INTERLEAVEFUNCTION then use that
     function and any configured CURLOPT_INTERLEAVEDATA to write out the RTP
     data. Otherwise, use the CURLOPT_WRITEFUNCTION with the CURLOPT_WRITEDATA
     pointer to write out the RTP data. */
  if(data->set.fwrite_rtp) {
    writeit = data->set.fwrite_rtp;
    user_ptr = data->set.rtp_out;
  }
  else {
    writeit = data->set.fwrite_func;
    user_ptr = data->set.out;
  }

  Curl_set_in_callback(data, true);
  wrote = writeit((char *)ptr, 1, len, user_ptr);
  Curl_set_in_callback(data, false);

  if(CURL_WRITEFUNC_PAUSE == wrote) {
    failf(data, "Cannot pause RTP");
    return CURLE_WRITE_ERROR;
  }

  if(wrote != len) {
    failf(data, "Failed writing RTP data");
    return CURLE_WRITE_ERROR;
  }

  return CURLE_OK;
}

CURLcode Curl_rtsp_parseheader(struct Curl_easy *data, char *header)
{
  if(checkprefix("CSeq:", header)) {
    long CSeq = 0;
    char *endp;
    char *p = &header[5];
    while(ISBLANK(*p))
      p++;
    CSeq = strtol(p, &endp, 10);
    if(p != endp) {
      struct RTSP *rtsp = data->req.p.rtsp;
      rtsp->CSeq_recv = CSeq; /* mark the request */
      data->state.rtsp_CSeq_recv = CSeq; /* update the handle */
    }
    else {
      failf(data, "Unable to read the CSeq header: [%s]", header);
      return CURLE_RTSP_CSEQ_ERROR;
    }
  }
  else if(checkprefix("Session:", header)) {
    char *start;
    char *end;
    size_t idlen;

    /* Find the first non-space letter */
    start = header + 8;
    while(*start && ISBLANK(*start))
      start++;

    if(!*start) {
      failf(data, "Got a blank Session ID");
      return CURLE_RTSP_SESSION_ERROR;
    }

    /* Find the end of Session ID
     *
     * Allow any non whitespace content, up to the field separator or end of
     * line. RFC 2326 isn't 100% clear on the session ID and for example
     * gstreamer does url-encoded session ID's not covered by the standard.
     */
    end = start;
    while(*end && *end != ';' && !ISSPACE(*end))
      end++;
    idlen = end - start;

    if(data->set.str[STRING_RTSP_SESSION_ID]) {

      /* If the Session ID is set, then compare */
      if(strlen(data->set.str[STRING_RTSP_SESSION_ID]) != idlen ||
         strncmp(start, data->set.str[STRING_RTSP_SESSION_ID], idlen)) {
        failf(data, "Got RTSP Session ID Line [%s], but wanted ID [%s]",
              start, data->set.str[STRING_RTSP_SESSION_ID]);
        return CURLE_RTSP_SESSION_ERROR;
      }
    }
    else {
      /* If the Session ID is not set, and we find it in a response, then set
       * it.
       */

      /* Copy the id substring into a new buffer */
      data->set.str[STRING_RTSP_SESSION_ID] = Curl_memdup0(start, idlen);
      if(!data->set.str[STRING_RTSP_SESSION_ID])
        return CURLE_OUT_OF_MEMORY;
    }
  }
  else if(checkprefix("Transport:", header)) {
    CURLcode result;
    result = rtsp_parse_transport(data, header + 10);
    if(result)
      return result;
  }
  return CURLE_OK;
}

static
CURLcode rtsp_parse_transport(struct Curl_easy *data, char *transport)
{
  /* If we receive multiple Transport response-headers, the linterleaved
     channels of each response header is recorded and used together for
     subsequent data validity checks.*/
  /* e.g.: ' RTP/AVP/TCP;unicast;interleaved=5-6' */
  char *start;
  char *end;
  start = transport;
  while(start && *start) {
    while(*start && ISBLANK(*start) )
      start++;
    end = strchr(start, ';');
    if(checkprefix("interleaved=", start)) {
      long chan1, chan2, chan;
      char *endp;
      char *p = start + 12;
      chan1 = strtol(p, &endp, 10);
      if(p != endp && chan1 >= 0 && chan1 <= 255) {
        unsigned char *rtp_channel_mask = data->state.rtp_channel_mask;
        chan2 = chan1;
        if(*endp == '-') {
          p = endp + 1;
          chan2 = strtol(p, &endp, 10);
          if(p == endp || chan2 < 0 || chan2 > 255) {
            infof(data, "Unable to read the interleaved parameter from "
                  "Transport header: [%s]", transport);
            chan2 = chan1;
          }
        }
        for(chan = chan1; chan <= chan2; chan++) {
          long idx = chan / 8;
          long off = chan % 8;
          rtp_channel_mask[idx] |= (unsigned char)(1 << off);
        }
      }
      else {
        infof(data, "Unable to read the interleaved parameter from "
              "Transport header: [%s]", transport);
      }
      break;
    }
    /* skip to next parameter */
    start = (!end) ? end : (end + 1);
  }
  return CURLE_OK;
}


#endif /* CURL_DISABLE_RTSP or using Hyper */
