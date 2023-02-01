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

#include "http_proxy.h"

#if !defined(CURL_DISABLE_PROXY)

#include <curl/curl.h>
#ifdef USE_HYPER
#include <hyper.h>
#endif
#include "sendf.h"
#include "http.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "cfilters.h"
#include "connect.h"
#include "curlx.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#if !defined(CURL_DISABLE_HTTP)

typedef enum {
    TUNNEL_INIT,     /* init/default/no tunnel state */
    TUNNEL_CONNECT,  /* CONNECT request is being send */
    TUNNEL_RECEIVE,  /* CONNECT answer is being received */
    TUNNEL_RESPONSE, /* CONNECT response received completely */
    TUNNEL_ESTABLISHED,
    TUNNEL_FAILED
} tunnel_state;

/* struct for HTTP CONNECT tunneling */
struct tunnel_state {
  int sockindex;
  const char *hostname;
  int remote_port;
  struct HTTP CONNECT;
  struct dynbuf rcvbuf;
  struct dynbuf req;
  size_t nsend;
  size_t headerlines;
  enum keeponval {
    KEEPON_DONE,
    KEEPON_CONNECT,
    KEEPON_IGNORE
  } keepon;
  curl_off_t cl; /* size of content to read and ignore */
  tunnel_state tunnel_state;
  BIT(chunked_encoding);
  BIT(close_connection);
};


static bool tunnel_is_established(struct tunnel_state *ts)
{
  return ts && (ts->tunnel_state == TUNNEL_ESTABLISHED);
}

static bool tunnel_is_failed(struct tunnel_state *ts)
{
  return ts && (ts->tunnel_state == TUNNEL_FAILED);
}

static CURLcode tunnel_reinit(struct tunnel_state *ts,
                              struct connectdata *conn,
                              struct Curl_easy *data)
{
  (void)data;
  DEBUGASSERT(ts);
  Curl_dyn_reset(&ts->rcvbuf);
  Curl_dyn_reset(&ts->req);
  ts->tunnel_state = TUNNEL_INIT;
  ts->keepon = KEEPON_CONNECT;
  ts->cl = 0;
  ts->close_connection = FALSE;

  if(conn->bits.conn_to_host)
    ts->hostname = conn->conn_to_host.name;
  else if(ts->sockindex == SECONDARYSOCKET)
    ts->hostname = conn->secondaryhostname;
  else
    ts->hostname = conn->host.name;

  if(ts->sockindex == SECONDARYSOCKET)
    ts->remote_port = conn->secondary_port;
  else if(conn->bits.conn_to_port)
    ts->remote_port = conn->conn_to_port;
  else
    ts->remote_port = conn->remote_port;

  return CURLE_OK;
}

static CURLcode tunnel_init(struct tunnel_state **pts,
                            struct Curl_easy *data,
                            struct connectdata *conn,
                            int sockindex)
{
  struct tunnel_state *ts;
  CURLcode result;

  if(conn->handler->flags & PROTOPT_NOTCPPROXY) {
    failf(data, "%s cannot be done over CONNECT", conn->handler->scheme);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  /* we might need the upload buffer for streaming a partial request */
  result = Curl_get_upload_buffer(data);
  if(result)
    return result;

  ts = calloc(1, sizeof(*ts));
  if(!ts)
    return CURLE_OUT_OF_MEMORY;

  ts->sockindex = sockindex;
  infof(data, "allocate connect buffer");

  Curl_dyn_init(&ts->rcvbuf, DYN_PROXY_CONNECT_HEADERS);
  Curl_dyn_init(&ts->req, DYN_HTTP_REQUEST);

  *pts =  ts;
  connkeep(conn, "HTTP proxy CONNECT");
  return tunnel_reinit(ts, conn, data);
}

static void tunnel_go_state(struct Curl_cfilter *cf,
                            struct tunnel_state *ts,
                            tunnel_state new_state,
                            struct Curl_easy *data)
{
  if(ts->tunnel_state == new_state)
    return;
  /* leaving this one */
  switch(ts->tunnel_state) {
  case TUNNEL_CONNECT:
    data->req.ignorebody = FALSE;
    break;
  default:
    break;
  }
  /* entering this one */
  switch(new_state) {
  case TUNNEL_INIT:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'init'"));
    tunnel_reinit(ts, cf->conn, data);
    break;

  case TUNNEL_CONNECT:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'connect'"));
    ts->tunnel_state = TUNNEL_CONNECT;
    ts->keepon = KEEPON_CONNECT;
    Curl_dyn_reset(&ts->rcvbuf);
    break;

  case TUNNEL_RECEIVE:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'receive'"));
    ts->tunnel_state = TUNNEL_RECEIVE;
    break;

  case TUNNEL_RESPONSE:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'response'"));
    ts->tunnel_state = TUNNEL_RESPONSE;
    break;

  case TUNNEL_ESTABLISHED:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'established'"));
    infof(data, "CONNECT phase completed");
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    /* FALLTHROUGH */
  case TUNNEL_FAILED:
    DEBUGF(LOG_CF(data, cf, "new tunnel state 'failed'"));
    ts->tunnel_state = new_state;
    Curl_dyn_reset(&ts->rcvbuf);
    Curl_dyn_reset(&ts->req);
    /* restore the protocol pointer */
    data->info.httpcode = 0; /* clear it as it might've been used for the
                                proxy */
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it isn't accidentally used for the document request
       after we've connected. So let's free and clear it here. */
    Curl_safefree(data->state.aptr.proxyuserpwd);
    data->state.aptr.proxyuserpwd = NULL;
#ifdef USE_HYPER
    data->state.hconnect = FALSE;
#endif
    break;
  }
}

static void tunnel_free(struct Curl_cfilter *cf,
                        struct Curl_easy *data)
{
  struct tunnel_state *ts = cf->ctx;
  if(ts) {
    tunnel_go_state(cf, ts, TUNNEL_FAILED, data);
    Curl_dyn_free(&ts->rcvbuf);
    Curl_dyn_free(&ts->req);
    free(ts);
    cf->ctx = NULL;
  }
}

static CURLcode CONNECT_host(struct Curl_easy *data,
                             struct connectdata *conn,
                             const char *hostname,
                             int remote_port,
                             char **connecthostp,
                             char **hostp)
{
  char *hostheader; /* for CONNECT */
  char *host = NULL; /* Host: */
  bool ipv6_ip = conn->bits.ipv6_ip;

  /* the hostname may be different */
  if(hostname != conn->host.name)
    ipv6_ip = (strchr(hostname, ':') != NULL);
  hostheader = /* host:port with IPv6 support */
    aprintf("%s%s%s:%d", ipv6_ip?"[":"", hostname, ipv6_ip?"]":"",
            remote_port);
  if(!hostheader)
    return CURLE_OUT_OF_MEMORY;

  if(!Curl_checkProxyheaders(data, conn, STRCONST("Host"))) {
    host = aprintf("Host: %s\r\n", hostheader);
    if(!host) {
      free(hostheader);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  *connecthostp = hostheader;
  *hostp = host;
  return CURLE_OK;
}

#ifndef USE_HYPER
static CURLcode start_CONNECT(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct tunnel_state *ts)
{
  struct connectdata *conn = cf->conn;
  char *hostheader = NULL;
  char *host = NULL;
  const char *httpv;
  CURLcode result;

  infof(data, "Establish HTTP proxy tunnel to %s:%d",
        ts->hostname, ts->remote_port);

    /* This only happens if we've looped here due to authentication
       reasons, and we don't really use the newly cloned URL here
       then. Just free() it. */
  Curl_safefree(data->req.newurl);

  result = CONNECT_host(data, conn,
                        ts->hostname, ts->remote_port,
                        &hostheader, &host);
  if(result)
    goto out;

  /* Setup the proxy-authorization header, if any */
  result = Curl_http_output_auth(data, conn, "CONNECT", HTTPREQ_GET,
                                 hostheader, TRUE);
  if(result)
    goto out;

  httpv = (conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0) ? "1.0" : "1.1";

  result =
      Curl_dyn_addf(&ts->req,
                    "CONNECT %s HTTP/%s\r\n"
                    "%s"  /* Host: */
                    "%s", /* Proxy-Authorization */
                    hostheader,
                    httpv,
                    host?host:"",
                    data->state.aptr.proxyuserpwd?
                    data->state.aptr.proxyuserpwd:"");
  if(result)
    goto out;

  if(!Curl_checkProxyheaders(data, conn, STRCONST("User-Agent"))
     && data->set.str[STRING_USERAGENT])
    result = Curl_dyn_addf(&ts->req, "User-Agent: %s\r\n",
                           data->set.str[STRING_USERAGENT]);
  if(result)
    goto out;

  if(!Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection")))
    result = Curl_dyn_addn(&ts->req,
                           STRCONST("Proxy-Connection: Keep-Alive\r\n"));
  if(result)
    goto out;

  result = Curl_add_custom_headers(data, TRUE, &ts->req);
  if(result)
    goto out;

  /* CRLF terminate the request */
  result = Curl_dyn_addn(&ts->req, STRCONST("\r\n"));
  if(result)
    goto out;

  /* Send the connect request to the proxy */
  result = Curl_buffer_send(&ts->req, data, &ts->CONNECT,
                            &data->info.request_size, 0,
                            ts->sockindex);
  ts->headerlines = 0;

out:
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  free(host);
  free(hostheader);
  return result;
}

static CURLcode send_CONNECT(struct Curl_easy *data,
                             struct connectdata *conn,
                             struct tunnel_state *ts,
                             bool *done)
{
  struct SingleRequest *k = &data->req;
  struct HTTP *http = &ts->CONNECT;
  CURLcode result = CURLE_OK;

  if(http->sending != HTTPSEND_REQUEST)
    goto out;

  if(!ts->nsend) {
    size_t fillcount;
    k->upload_fromhere = data->state.ulbuf;
    result = Curl_fillreadbuffer(data, data->set.upload_buffer_size,
                                 &fillcount);
    if(result)
      goto out;
    ts->nsend = fillcount;
  }
  if(ts->nsend) {
    ssize_t bytes_written;
    /* write to socket (send away data) */
    result = Curl_write(data,
                        conn->writesockfd,  /* socket to send to */
                        k->upload_fromhere, /* buffer pointer */
                        ts->nsend,          /* buffer size */
                        &bytes_written);    /* actually sent */
    if(result)
      goto out;
    /* send to debug callback! */
    Curl_debug(data, CURLINFO_HEADER_OUT,
               k->upload_fromhere, bytes_written);

    ts->nsend -= bytes_written;
    k->upload_fromhere += bytes_written;
  }
  if(!ts->nsend)
    http->sending = HTTPSEND_NADA;

out:
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  *done = (http->sending != HTTPSEND_REQUEST);
  return result;
}

static CURLcode on_resp_header(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct tunnel_state *ts,
                               const char *header)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  int subversion = 0;
  (void)cf;

  if((checkprefix("WWW-Authenticate:", header) &&
      (401 == k->httpcode)) ||
     (checkprefix("Proxy-authenticate:", header) &&
      (407 == k->httpcode))) {

    bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
    char *auth = Curl_copy_header_value(header);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;

    DEBUGF(LOG_CF(data, cf, "CONNECT: fwd auth header '%s'", header));
    result = Curl_http_input_auth(data, proxy, auth);

    free(auth);

    if(result)
      return result;
  }
  else if(checkprefix("Content-Length:", header)) {
    if(k->httpcode/100 == 2) {
      /* A client MUST ignore any Content-Length or Transfer-Encoding
         header fields received in a successful response to CONNECT.
         "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
      infof(data, "Ignoring Content-Length in CONNECT %03d response",
            k->httpcode);
    }
    else {
      (void)curlx_strtoofft(header + strlen("Content-Length:"),
                            NULL, 10, &ts->cl);
    }
  }
  else if(Curl_compareheader(header,
                             STRCONST("Connection:"), STRCONST("close")))
    ts->close_connection = TRUE;
  else if(checkprefix("Transfer-Encoding:", header)) {
    if(k->httpcode/100 == 2) {
      /* A client MUST ignore any Content-Length or Transfer-Encoding
         header fields received in a successful response to CONNECT.
         "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
      infof(data, "Ignoring Transfer-Encoding in "
            "CONNECT %03d response", k->httpcode);
    }
    else if(Curl_compareheader(header,
                               STRCONST("Transfer-Encoding:"),
                               STRCONST("chunked"))) {
      infof(data, "CONNECT responded chunked");
      ts->chunked_encoding = TRUE;
      /* init our chunky engine */
      Curl_httpchunk_init(data);
    }
  }
  else if(Curl_compareheader(header,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("close")))
    ts->close_connection = TRUE;
  else if(2 == sscanf(header, "HTTP/1.%d %d",
                      &subversion,
                      &k->httpcode)) {
    /* store the HTTP code from the proxy */
    data->info.httpproxycode = k->httpcode;
  }
  return result;
}

static CURLcode recv_CONNECT_resp(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct tunnel_state *ts,
                                  bool *done)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  curl_socket_t tunnelsocket = Curl_conn_cf_get_socket(cf, data);
  char *linep;
  size_t perline;
  int error;

#define SELECT_OK      0
#define SELECT_ERROR   1

  error = SELECT_OK;
  *done = FALSE;

  if(!Curl_conn_data_pending(data, ts->sockindex))
    return CURLE_OK;

  while(ts->keepon) {
    ssize_t gotbytes;
    char byte;

    /* Read one byte at a time to avoid a race condition. Wait at most one
       second before looping to ensure continuous pgrsUpdates. */
    result = Curl_read(data, tunnelsocket, &byte, 1, &gotbytes);
    if(result == CURLE_AGAIN)
      /* socket buffer drained, return */
      return CURLE_OK;

    if(Curl_pgrsUpdate(data))
      return CURLE_ABORTED_BY_CALLBACK;

    if(result) {
      ts->keepon = KEEPON_DONE;
      break;
    }

    if(gotbytes <= 0) {
      if(data->set.proxyauth && data->state.authproxy.avail &&
         data->state.aptr.proxyuserpwd) {
        /* proxy auth was requested and there was proxy auth available,
           then deem this as "mere" proxy disconnect */
        ts->close_connection = TRUE;
        infof(data, "Proxy CONNECT connection closed");
      }
      else {
        error = SELECT_ERROR;
        failf(data, "Proxy CONNECT aborted");
      }
      ts->keepon = KEEPON_DONE;
      break;
    }

    if(ts->keepon == KEEPON_IGNORE) {
      /* This means we are currently ignoring a response-body */

      if(ts->cl) {
        /* A Content-Length based body: simply count down the counter
           and make sure to break out of the loop when we're done! */
        ts->cl--;
        if(ts->cl <= 0) {
          ts->keepon = KEEPON_DONE;
          break;
        }
      }
      else {
        /* chunked-encoded body, so we need to do the chunked dance
           properly to know when the end of the body is reached */
        CHUNKcode r;
        CURLcode extra;
        ssize_t tookcareof = 0;

        /* now parse the chunked piece of data so that we can
           properly tell when the stream ends */
        r = Curl_httpchunk_read(data, &byte, 1, &tookcareof, &extra);
        if(r == CHUNKE_STOP) {
          /* we're done reading chunks! */
          infof(data, "chunk reading DONE");
          ts->keepon = KEEPON_DONE;
        }
      }
      continue;
    }

    if(Curl_dyn_addn(&ts->rcvbuf, &byte, 1)) {
      failf(data, "CONNECT response too large");
      return CURLE_RECV_ERROR;
    }

    /* if this is not the end of a header line then continue */
    if(byte != 0x0a)
      continue;

    ts->headerlines++;
    linep = Curl_dyn_ptr(&ts->rcvbuf);
    perline = Curl_dyn_len(&ts->rcvbuf); /* amount of bytes in this line */

    /* output debug if that is requested */
    Curl_debug(data, CURLINFO_HEADER_IN, linep, perline);

    if(!data->set.suppress_connect_headers) {
      /* send the header to the callback */
      int writetype = CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT |
        (data->set.include_header ? CLIENTWRITE_BODY : 0) |
        (ts->headerlines == 1 ? CLIENTWRITE_STATUS : 0);

      result = Curl_client_write(data, writetype, linep, perline);
      if(result)
        return result;
    }

    data->info.header_size += (long)perline;

    /* Newlines are CRLF, so the CR is ignored as the line isn't
       really terminated until the LF comes. Treat a following CR
       as end-of-headers as well.*/

    if(('\r' == linep[0]) ||
       ('\n' == linep[0])) {
      /* end of response-headers from the proxy */

      if((407 == k->httpcode) && !data->state.authproblem) {
        /* If we get a 407 response code with content length
           when we have no auth problem, we must ignore the
           whole response-body */
        ts->keepon = KEEPON_IGNORE;

        if(ts->cl) {
          infof(data, "Ignore %" CURL_FORMAT_CURL_OFF_T
                " bytes of response-body", ts->cl);
        }
        else if(ts->chunked_encoding) {
          CHUNKcode r;
          CURLcode extra;

          infof(data, "Ignore chunked response-body");

          /* We set ignorebody true here since the chunked decoder
             function will acknowledge that. Pay attention so that this is
             cleared again when this function returns! */
          k->ignorebody = TRUE;

          if(linep[1] == '\n')
            /* this can only be a LF if the letter at index 0 was a CR */
            linep++;

          /* now parse the chunked piece of data so that we can properly
             tell when the stream ends */
          r = Curl_httpchunk_read(data, linep + 1, 1, &gotbytes,
                                  &extra);
          if(r == CHUNKE_STOP) {
            /* we're done reading chunks! */
            infof(data, "chunk reading DONE");
            ts->keepon = KEEPON_DONE;
          }
        }
        else {
          /* without content-length or chunked encoding, we
             can't keep the connection alive since the close is
             the end signal so we bail out at once instead */
          DEBUGF(LOG_CF(data, cf, "CONNECT: no content-length or chunked"));
          ts->keepon = KEEPON_DONE;
        }
      }
      else {
        ts->keepon = KEEPON_DONE;
      }

      DEBUGASSERT(ts->keepon == KEEPON_IGNORE
                  || ts->keepon == KEEPON_DONE);
      continue;
    }

    result = on_resp_header(cf, data, ts, linep);
    if(result)
      return result;

    Curl_dyn_reset(&ts->rcvbuf);
  } /* while there's buffer left and loop is requested */

  if(error)
    result = CURLE_RECV_ERROR;
  *done = (ts->keepon == KEEPON_DONE);
  if(!result && *done && data->info.httpproxycode/100 != 2) {
    /* Deal with the possibly already received authenticate
       headers. 'newurl' is set to a new URL if we must loop. */
    result = Curl_http_auth_act(data);
  }
  return result;
}

#else /* USE_HYPER */
/* The Hyper version of CONNECT */
static CURLcode start_CONNECT(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct tunnel_state *ts)
{
  struct connectdata *conn = cf->conn;
  struct hyptransfer *h = &data->hyp;
  curl_socket_t tunnelsocket = Curl_conn_cf_get_socket(cf, data);
  hyper_io *io = NULL;
  hyper_request *req = NULL;
  hyper_headers *headers = NULL;
  hyper_clientconn_options *options = NULL;
  hyper_task *handshake = NULL;
  hyper_task *task = NULL; /* for the handshake */
  hyper_clientconn *client = NULL;
  hyper_task *sendtask = NULL; /* for the send */
  char *hostheader = NULL; /* for CONNECT */
  char *host = NULL; /* Host: */
  CURLcode result = CURLE_OUT_OF_MEMORY;

  io = hyper_io_new();
  if(!io) {
    failf(data, "Couldn't create hyper IO");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  /* tell Hyper how to read/write network data */
  hyper_io_set_userdata(io, data);
  hyper_io_set_read(io, Curl_hyper_recv);
  hyper_io_set_write(io, Curl_hyper_send);
  conn->sockfd = tunnelsocket;

  data->state.hconnect = TRUE;

  /* create an executor to poll futures */
  if(!h->exec) {
    h->exec = hyper_executor_new();
    if(!h->exec) {
      failf(data, "Couldn't create hyper executor");
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
  }

  options = hyper_clientconn_options_new();
  hyper_clientconn_options_set_preserve_header_case(options, 1);
  hyper_clientconn_options_set_preserve_header_order(options, 1);

  if(!options) {
    failf(data, "Couldn't create hyper client options");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  hyper_clientconn_options_exec(options, h->exec);

  /* "Both the `io` and the `options` are consumed in this function
     call" */
  handshake = hyper_clientconn_handshake(io, options);
  if(!handshake) {
    failf(data, "Couldn't create hyper client handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  io = NULL;
  options = NULL;

  if(HYPERE_OK != hyper_executor_push(h->exec, handshake)) {
    failf(data, "Couldn't hyper_executor_push the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  handshake = NULL; /* ownership passed on */

  task = hyper_executor_poll(h->exec);
  if(!task) {
    failf(data, "Couldn't hyper_executor_poll the handshake");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  client = hyper_task_value(task);
  hyper_task_free(task);
  req = hyper_request_new();
  if(!req) {
    failf(data, "Couldn't hyper_request_new");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  if(hyper_request_set_method(req, (uint8_t *)"CONNECT",
                              strlen("CONNECT"))) {
    failf(data, "error setting method");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  infof(data, "Establish HTTP proxy tunnel to %s:%d",
        ts->hostname, ts->remote_port);

    /* This only happens if we've looped here due to authentication
       reasons, and we don't really use the newly cloned URL here
       then. Just free() it. */
  Curl_safefree(data->req.newurl);

  result = CONNECT_host(data, conn, ts->hostname, ts->remote_port,
                        &hostheader, &host);
  if(result)
    goto error;

  if(hyper_request_set_uri(req, (uint8_t *)hostheader,
                           strlen(hostheader))) {
    failf(data, "error setting path");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  if(data->set.verbose) {
    char *se = aprintf("CONNECT %s HTTP/1.1\r\n", hostheader);
    if(!se) {
      result = CURLE_OUT_OF_MEMORY;
      goto error;
    }
    Curl_debug(data, CURLINFO_HEADER_OUT, se, strlen(se));
    free(se);
  }
  /* Setup the proxy-authorization header, if any */
  result = Curl_http_output_auth(data, conn, "CONNECT", HTTPREQ_GET,
                                 hostheader, TRUE);
  if(result)
    goto error;
  Curl_safefree(hostheader);

  /* default is 1.1 */
  if((conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0) &&
     (HYPERE_OK != hyper_request_set_version(req,
                                             HYPER_HTTP_VERSION_1_0))) {
    failf(data, "error setting HTTP version");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  headers = hyper_request_headers(req);
  if(!headers) {
    failf(data, "hyper_request_headers");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }
  if(host) {
    result = Curl_hyper_header(data, headers, host);
    if(result)
      goto error;
    Curl_safefree(host);
  }

  if(data->state.aptr.proxyuserpwd) {
    result = Curl_hyper_header(data, headers,
                               data->state.aptr.proxyuserpwd);
    if(result)
      goto error;
  }

  if(!Curl_checkProxyheaders(data, conn, STRCONST("User-Agent")) &&
     data->set.str[STRING_USERAGENT]) {
    struct dynbuf ua;
    Curl_dyn_init(&ua, DYN_HTTP_REQUEST);
    result = Curl_dyn_addf(&ua, "User-Agent: %s\r\n",
                           data->set.str[STRING_USERAGENT]);
    if(result)
      goto error;
    result = Curl_hyper_header(data, headers, Curl_dyn_ptr(&ua));
    if(result)
      goto error;
    Curl_dyn_free(&ua);
  }

  if(!Curl_checkProxyheaders(data, conn, STRCONST("Proxy-Connection"))) {
    result = Curl_hyper_header(data, headers,
                               "Proxy-Connection: Keep-Alive");
    if(result)
      goto error;
  }

  result = Curl_add_custom_headers(data, TRUE, headers);
  if(result)
    goto error;

  sendtask = hyper_clientconn_send(client, req);
  if(!sendtask) {
    failf(data, "hyper_clientconn_send");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

  if(HYPERE_OK != hyper_executor_push(h->exec, sendtask)) {
    failf(data, "Couldn't hyper_executor_push the send");
    result = CURLE_OUT_OF_MEMORY;
    goto error;
  }

error:
  free(host);
  free(hostheader);
  if(io)
    hyper_io_free(io);
  if(options)
    hyper_clientconn_options_free(options);
  if(handshake)
    hyper_task_free(handshake);
  if(client)
    hyper_clientconn_free(client);
  return result;
}

static CURLcode send_CONNECT(struct Curl_easy *data,
                             struct connectdata *conn,
                             struct tunnel_state *ts,
                             bool *done)
{
  struct hyptransfer *h = &data->hyp;
  hyper_task *task = NULL;
  hyper_error *hypererr = NULL;
  CURLcode result = CURLE_OK;

  (void)ts;
  (void)conn;
  do {
    task = hyper_executor_poll(h->exec);
    if(task) {
      bool error = hyper_task_type(task) == HYPER_TASK_ERROR;
      if(error)
        hypererr = hyper_task_value(task);
      hyper_task_free(task);
      if(error) {
        /* this could probably use a better error code? */
        result = CURLE_OUT_OF_MEMORY;
        goto error;
      }
    }
  } while(task);
error:
  *done = (result == CURLE_OK);
  if(hypererr) {
    uint8_t errbuf[256];
    size_t errlen = hyper_error_print(hypererr, errbuf, sizeof(errbuf));
    failf(data, "Hyper: %.*s", (int)errlen, errbuf);
    hyper_error_free(hypererr);
  }
  return result;
}

static CURLcode recv_CONNECT_resp(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct tunnel_state *ts,
                                  bool *done)
{
  struct hyptransfer *h = &data->hyp;
  CURLcode result;
  int didwhat;

  (void)ts;
  *done = FALSE;
  result = Curl_hyper_stream(data, cf->conn, &didwhat, done,
                             CURL_CSELECT_IN | CURL_CSELECT_OUT);
  if(result || !*done)
    return result;
  if(h->exec) {
    hyper_executor_free(h->exec);
    h->exec = NULL;
  }
  if(h->read_waker) {
    hyper_waker_free(h->read_waker);
    h->read_waker = NULL;
  }
  if(h->write_waker) {
    hyper_waker_free(h->write_waker);
    h->write_waker = NULL;
  }
  return result;
}

#endif /* USE_HYPER */

static CURLcode CONNECT(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        struct tunnel_state *ts)
{
  struct connectdata *conn = cf->conn;
  CURLcode result;
  bool done;

  if(tunnel_is_established(ts))
    return CURLE_OK;
  if(tunnel_is_failed(ts))
    return CURLE_RECV_ERROR; /* Need a cfilter close and new bootstrap */

  do {
    timediff_t check;

    check = Curl_timeleft(data, NULL, TRUE);
    if(check <= 0) {
      failf(data, "Proxy CONNECT aborted due to timeout");
      result = CURLE_OPERATION_TIMEDOUT;
      goto out;
    }

    switch(ts->tunnel_state) {
    case TUNNEL_INIT:
      /* Prepare the CONNECT request and make a first attempt to send. */
      DEBUGF(LOG_CF(data, cf, "CONNECT start"));
      result = start_CONNECT(cf, data, ts);
      if(result)
        goto out;
      tunnel_go_state(cf, ts, TUNNEL_CONNECT, data);
      /* FALLTHROUGH */

    case TUNNEL_CONNECT:
      /* see that the request is completely sent */
      DEBUGF(LOG_CF(data, cf, "CONNECT send"));
      result = send_CONNECT(data, cf->conn, ts, &done);
      if(result || !done)
        goto out;
      tunnel_go_state(cf, ts, TUNNEL_RECEIVE, data);
      /* FALLTHROUGH */

    case TUNNEL_RECEIVE:
      /* read what is there */
      DEBUGF(LOG_CF(data, cf, "CONNECT receive"));
      result = recv_CONNECT_resp(cf, data, ts, &done);
      if(Curl_pgrsUpdate(data)) {
        result = CURLE_ABORTED_BY_CALLBACK;
        goto out;
      }
      /* error or not complete yet. return for more multi-multi */
      if(result || !done)
        goto out;
      /* got it */
      tunnel_go_state(cf, ts, TUNNEL_RESPONSE, data);
      /* FALLTHROUGH */

    case TUNNEL_RESPONSE:
      DEBUGF(LOG_CF(data, cf, "CONNECT response"));
      if(data->req.newurl) {
        /* not the "final" response, we need to do a follow up request.
         * If the other side indicated a connection close, or if someone
         * else told us to close this connection, do so now.
         */
        if(ts->close_connection || conn->bits.close) {
          /* Close this filter and the sub-chain, re-connect the
           * sub-chain and continue. Closing this filter will
           * reset our tunnel state. To avoid recursion, we return
           * and expect to be called again.
           */
          DEBUGF(LOG_CF(data, cf, "CONNECT need to close+open"));
          infof(data, "Connect me again please");
          Curl_conn_cf_close(cf, data);
          connkeep(conn, "HTTP proxy CONNECT");
          result = Curl_conn_cf_connect(cf->next, data, FALSE, &done);
          goto out;
        }
        else {
          /* staying on this connection, reset state */
          tunnel_go_state(cf, ts, TUNNEL_INIT, data);
        }
      }
      break;

    default:
      break;
    }

  } while(data->req.newurl);

  DEBUGASSERT(ts->tunnel_state == TUNNEL_RESPONSE);
  if(data->info.httpproxycode/100 != 2) {
    /* a non-2xx response and we have no next url to try. */
    free(data->req.newurl);
    data->req.newurl = NULL;
    /* failure, close this connection to avoid re-use */
    streamclose(conn, "proxy CONNECT failure");
    tunnel_go_state(cf, ts, TUNNEL_FAILED, data);
    failf(data, "CONNECT tunnel failed, response %d", data->req.httpcode);
    return CURLE_RECV_ERROR;
  }
  /* 2xx response, SUCCESS! */
  tunnel_go_state(cf, ts, TUNNEL_ESTABLISHED, data);
  infof(data, "CONNECT tunnel established, response %d",
        data->info.httpproxycode);
  result = CURLE_OK;

out:
  if(result)
    tunnel_go_state(cf, ts, TUNNEL_FAILED, data);
  return result;
}

static CURLcode http_proxy_cf_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool blocking, bool *done)
{
  CURLcode result;
  struct tunnel_state *ts = cf->ctx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  DEBUGF(LOG_CF(data, cf, "connect"));
  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    return result;

  DEBUGF(LOG_CF(data, cf, "subchain is connected"));
  /* TODO: can we do blocking? */
  /* We want "seamless" operations through HTTP proxy tunnel */

  /* for the secondary socket (FTP), use the "connect to host"
   * but ignore the "connect to port" (use the secondary port)
   */
  *done = FALSE;
  if(!ts) {
    result = tunnel_init(&ts, data, cf->conn, cf->sockindex);
    if(result)
      return result;
    cf->ctx = ts;
  }

  result = CONNECT(cf, data, ts);
  if(result)
    goto out;
  Curl_safefree(data->state.aptr.proxyuserpwd);

out:
  *done = (result == CURLE_OK) && tunnel_is_established(cf->ctx);
  if (*done) {
    cf->connected = TRUE;
    tunnel_free(cf, data);
  }
  return result;
}

static void http_proxy_cf_get_host(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   const char **phost,
                                   const char **pdisplay_host,
                                   int *pport)
{
  (void)data;
  if(!cf->connected) {
    *phost = cf->conn->http_proxy.host.name;
    *pdisplay_host = cf->conn->http_proxy.host.dispname;
    *pport = (int)cf->conn->http_proxy.port;
  }
  else {
    cf->next->cft->get_host(cf->next, data, phost, pdisplay_host, pport);
  }
}

static int http_proxy_cf_get_select_socks(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          curl_socket_t *socks)
{
  struct tunnel_state *ts = cf->ctx;
  int fds;

  fds = cf->next->cft->get_select_socks(cf->next, data, socks);
  if(!fds && cf->next->connected && !cf->connected) {
    /* If we are not connected, but the filter "below" is
     * and not waiting on something, we are tunneling. */
    socks[0] = Curl_conn_cf_get_socket(cf, data);
    if(ts) {
      /* when we've sent a CONNECT to a proxy, we should rather either
         wait for the socket to become readable to be able to get the
         response headers or if we're still sending the request, wait
         for write. */
      if(ts->CONNECT.sending == HTTPSEND_REQUEST) {
        return GETSOCK_WRITESOCK(0);
      }
      return GETSOCK_READSOCK(0);
    }
    return GETSOCK_WRITESOCK(0);
  }
  return fds;
}

static void http_proxy_cf_destroy(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  DEBUGF(LOG_CF(data, cf, "destroy"));
  tunnel_free(cf, data);
}

static void http_proxy_cf_close(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  DEBUGASSERT(cf->next);
  DEBUGF(LOG_CF(data, cf, "close"));
  cf->connected = FALSE;
  cf->next->cft->close(cf->next, data);
  if(cf->ctx) {
    tunnel_go_state(cf, cf->ctx, TUNNEL_INIT, data);
  }
}


struct Curl_cftype Curl_cft_http_proxy = {
  "HTTP-PROXY",
  CF_TYPE_IP_CONNECT,
  0,
  http_proxy_cf_destroy,
  http_proxy_cf_connect,
  http_proxy_cf_close,
  http_proxy_cf_get_host,
  http_proxy_cf_get_select_socks,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

CURLcode Curl_conn_http_proxy_add(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = Curl_cf_create(&cf, &Curl_cft_http_proxy, NULL);
  if(!result)
    Curl_conn_cf_add(data, conn, sockindex, cf);
  return result;
}

CURLcode Curl_cf_http_proxy_insert_after(struct Curl_cfilter *cf_at,
                                         struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  (void)data;
  result = Curl_cf_create(&cf, &Curl_cft_http_proxy, NULL);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#endif /* ! CURL_DISABLE_HTTP */


typedef enum {
    HAPROXY_INIT,     /* init/default/no tunnel state */
    HAPROXY_SEND,     /* data_out being sent */
    HAPROXY_DONE      /* all work done */
} haproxy_state;

struct cf_haproxy_ctx {
  int state;
  struct dynbuf data_out;
};

static void cf_haproxy_ctx_reset(struct cf_haproxy_ctx *ctx)
{
  DEBUGASSERT(ctx);
  ctx->state = HAPROXY_INIT;
  Curl_dyn_reset(&ctx->data_out);
}

static void cf_haproxy_ctx_free(struct cf_haproxy_ctx *ctx)
{
  if(ctx) {
    Curl_dyn_free(&ctx->data_out);
    free(ctx);
  }
}

static CURLcode cf_haproxy_date_out_set(struct Curl_cfilter*cf,
                                        struct Curl_easy *data)
{
  struct cf_haproxy_ctx *ctx = cf->ctx;
  CURLcode result;
  const char *tcp_version;

  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->state == HAPROXY_INIT);
#ifdef USE_UNIX_SOCKETS
  if(cf->conn->unix_domain_socket)
    /* the buffer is large enough to hold this! */
    result = Curl_dyn_addn(&ctx->data_out, STRCONST("PROXY UNKNOWN\r\n"));
  else {
#endif /* USE_UNIX_SOCKETS */
  /* Emit the correct prefix for IPv6 */
  tcp_version = cf->conn->bits.ipv6 ? "TCP6" : "TCP4";

  result = Curl_dyn_addf(&ctx->data_out, "PROXY %s %s %s %i %i\r\n",
                         tcp_version,
                         data->info.conn_local_ip,
                         data->info.conn_primary_ip,
                         data->info.conn_local_port,
                         data->info.conn_primary_port);

#ifdef USE_UNIX_SOCKETS
  }
#endif /* USE_UNIX_SOCKETS */
  return result;
}

static CURLcode cf_haproxy_connect(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool blocking, bool *done)
{
  struct cf_haproxy_ctx *ctx = cf->ctx;
  CURLcode result;
  size_t len;

  DEBUGASSERT(ctx);
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    return result;

  switch(ctx->state) {
  case HAPROXY_INIT:
    result = cf_haproxy_date_out_set(cf, data);
    if(result)
      goto out;
    ctx->state = HAPROXY_SEND;
    /* FALLTHROUGH */
  case HAPROXY_SEND:
    len = Curl_dyn_len(&ctx->data_out);
    if(len > 0) {
      ssize_t written = Curl_conn_send(data, cf->sockindex,
                                       Curl_dyn_ptr(&ctx->data_out),
                                       len, &result);
      if(written < 0)
        goto out;
      Curl_dyn_tail(&ctx->data_out, len - (size_t)written);
      if(Curl_dyn_len(&ctx->data_out) > 0) {
        result = CURLE_OK;
        goto out;
      }
    }
    ctx->state = HAPROXY_DONE;
    /* FALLTHROUGH */
  default:
    Curl_dyn_free(&ctx->data_out);
    break;
  }

out:
  *done = (!result) && (ctx->state == HAPROXY_DONE);
  cf->connected = *done;
  return result;
}

static void cf_haproxy_destroy(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  (void)data;
  DEBUGF(LOG_CF(data, cf, "destroy"));
  cf_haproxy_ctx_free(cf->ctx);
}

static void cf_haproxy_close(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  DEBUGF(LOG_CF(data, cf, "close"));
  cf->connected = FALSE;
  cf_haproxy_ctx_reset(cf->ctx);
  if(cf->next)
    cf->next->cft->close(cf->next, data);
}

static int cf_haproxy_get_select_socks(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       curl_socket_t *socks)
{
  int fds;

  fds = cf->next->cft->get_select_socks(cf->next, data, socks);
  if(!fds && cf->next->connected && !cf->connected) {
    /* If we are not connected, but the filter "below" is
     * and not waiting on something, we are sending. */
    socks[0] = Curl_conn_cf_get_socket(cf, data);
    return GETSOCK_WRITESOCK(0);
  }
  return fds;
}


struct Curl_cftype Curl_cft_haproxy = {
  "HAPROXY",
  0,
  0,
  cf_haproxy_destroy,
  cf_haproxy_connect,
  cf_haproxy_close,
  Curl_cf_def_get_host,
  cf_haproxy_get_select_socks,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_haproxy_create(struct Curl_cfilter **pcf,
                                  struct Curl_easy *data)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_haproxy_ctx *ctx;
  CURLcode result;

  (void)data;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->state = HAPROXY_INIT;
  Curl_dyn_init(&ctx->data_out, DYN_HAXPROXY);

  result = Curl_cf_create(&cf, &Curl_cft_haproxy, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  cf_haproxy_ctx_free(ctx);
  *pcf = result? NULL : cf;
  return result;
}

CURLcode Curl_conn_haproxy_add(struct Curl_easy *data,
                               struct connectdata *conn,
                               int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_haproxy_create(&cf, data);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);

out:
  return result;
}

CURLcode Curl_cf_haproxy_insert_after(struct Curl_cfilter *cf_at,
                                      struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_haproxy_create(&cf, data);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);

out:
  return result;
}

#endif /* !CURL_DISABLE_PROXY */
