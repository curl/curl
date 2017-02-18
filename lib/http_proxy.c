/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include "urldata.h"
#include <curl/curl.h>
#include "http_proxy.h"
#include "sendf.h"
#include "http.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "non-ascii.h"
#include "connect.h"
#include "curlx.h"
#include "vtls/vtls.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Perform SSL initialization for HTTPS proxy.  Sets
 * proxy_ssl_connected connection bit when complete.  Can be
 * called multiple times.
 */
static CURLcode https_proxy_connect(struct connectdata *conn, int sockindex)
{
#ifdef USE_SSL
  CURLcode result = CURLE_OK;
  DEBUGASSERT(conn->http_proxy.proxytype == CURLPROXY_HTTPS);
  if(!conn->bits.proxy_ssl_connected[sockindex]) {
    /* perform SSL initialization for this socket */
    result =
      Curl_ssl_connect_nonblocking(conn, sockindex,
                                   &conn->bits.proxy_ssl_connected[sockindex]);
    if(result)
      conn->bits.close = TRUE; /* a failed connection is marked for closure to
                                  prevent (bad) re-use or similar */
  }
  return result;
#else
  (void) conn;
  (void) sockindex;
  return CURLE_NOT_BUILT_IN;
#endif
}

CURLcode Curl_proxy_connect(struct connectdata *conn, int sockindex)
{
  if(conn->http_proxy.proxytype == CURLPROXY_HTTPS) {
    const CURLcode result = https_proxy_connect(conn, sockindex);
    if(result)
      return result;
    if(!conn->bits.proxy_ssl_connected[sockindex])
      return result; /* wait for HTTPS proxy SSL initialization to complete */
  }

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
#ifndef CURL_DISABLE_PROXY
    /* for [protocol] tunneled through HTTP proxy */
    struct HTTP http_proxy;
    void *prot_save;
    const char *hostname;
    int remote_port;
    CURLcode result;

    /* BLOCKING */
    /* We want "seamless" operations through HTTP proxy tunnel */

    /* Curl_proxyCONNECT is based on a pointer to a struct HTTP at the
     * member conn->proto.http; we want [protocol] through HTTP and we have
     * to change the member temporarily for connecting to the HTTP
     * proxy. After Curl_proxyCONNECT we have to set back the member to the
     * original pointer
     *
     * This function might be called several times in the multi interface case
     * if the proxy's CONNECT response is not instant.
     */
    prot_save = conn->data->req.protop;
    memset(&http_proxy, 0, sizeof(http_proxy));
    conn->data->req.protop = &http_proxy;
    connkeep(conn, "HTTP proxy CONNECT");

    /* for the secondary socket (FTP), use the "connect to host"
     * but ignore the "connect to port" (use the secondary port)
     */

    if(conn->bits.conn_to_host)
      hostname = conn->conn_to_host.name;
    else if(sockindex == SECONDARYSOCKET)
      hostname = conn->secondaryhostname;
    else
      hostname = conn->host.name;

    if(sockindex == SECONDARYSOCKET)
      remote_port = conn->secondary_port;
    else if(conn->bits.conn_to_port)
      remote_port = conn->conn_to_port;
    else
      remote_port = conn->remote_port;
    result = Curl_proxyCONNECT(conn, sockindex, hostname,
                               remote_port, FALSE);
    conn->data->req.protop = prot_save;
    if(CURLE_OK != result)
      return result;
    Curl_safefree(conn->allocptr.proxyuserpwd);
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }
  /* no HTTP tunnel proxy, just return */
  return CURLE_OK;
}

/*
 * Curl_proxyCONNECT() requires that we're connected to a HTTP proxy. This
 * function will issue the necessary commands to get a seamless tunnel through
 * this proxy. After that, the socket can be used just as a normal socket.
 *
 * 'blocking' set to TRUE means that this function will do the entire CONNECT
 * + response in a blocking fashion. Should be avoided!
 */

CURLcode Curl_proxyCONNECT(struct connectdata *conn,
                           int sockindex,
                           const char *hostname,
                           int remote_port,
                           bool blocking)
{
  int subversion=0;
  struct Curl_easy *data=conn->data;
  struct SingleRequest *k = &data->req;
  CURLcode result;
  curl_socket_t tunnelsocket = conn->sock[sockindex];
  curl_off_t cl=0;
  bool closeConnection = FALSE;
  bool chunked_encoding = FALSE;
  time_t check;

#define SELECT_OK      0
#define SELECT_ERROR   1
#define SELECT_TIMEOUT 2
  int error = SELECT_OK;

  if(conn->tunnel_state[sockindex] == TUNNEL_COMPLETE)
    return CURLE_OK; /* CONNECT is already completed */

  conn->bits.proxy_connect_closed = FALSE;

  do {
    if(TUNNEL_INIT == conn->tunnel_state[sockindex]) {
      /* BEGIN CONNECT PHASE */
      char *host_port;
      Curl_send_buffer *req_buffer;

      infof(data, "Establish HTTP proxy tunnel to %s:%hu\n",
            hostname, remote_port);

        /* This only happens if we've looped here due to authentication
           reasons, and we don't really use the newly cloned URL here
           then. Just free() it. */
      free(data->req.newurl);
      data->req.newurl = NULL;

      /* initialize a dynamic send-buffer */
      req_buffer = Curl_add_buffer_init();

      if(!req_buffer)
        return CURLE_OUT_OF_MEMORY;

      host_port = aprintf("%s:%hu", hostname, remote_port);
      if(!host_port) {
        Curl_add_buffer_free(req_buffer);
        return CURLE_OUT_OF_MEMORY;
      }

      /* Setup the proxy-authorization header, if any */
      result = Curl_http_output_auth(conn, "CONNECT", host_port, TRUE);

      free(host_port);

      if(!result) {
        char *host = NULL;
        const char *proxyconn="";
        const char *useragent="";
        const char *http = (conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0) ?
          "1.0" : "1.1";
        bool ipv6_ip = conn->bits.ipv6_ip;
        char *hostheader;

        /* the hostname may be different */
        if(hostname != conn->host.name)
          ipv6_ip = (strchr(hostname, ':') != NULL);
        hostheader= /* host:port with IPv6 support */
          aprintf("%s%s%s:%hu", ipv6_ip?"[":"", hostname, ipv6_ip?"]":"",
                  remote_port);
        if(!hostheader) {
          Curl_add_buffer_free(req_buffer);
          return CURLE_OUT_OF_MEMORY;
        }

        if(!Curl_checkProxyheaders(conn, "Host:")) {
          host = aprintf("Host: %s\r\n", hostheader);
          if(!host) {
            free(hostheader);
            Curl_add_buffer_free(req_buffer);
            return CURLE_OUT_OF_MEMORY;
          }
        }
        if(!Curl_checkProxyheaders(conn, "Proxy-Connection:"))
          proxyconn = "Proxy-Connection: Keep-Alive\r\n";

        if(!Curl_checkProxyheaders(conn, "User-Agent:") &&
           data->set.str[STRING_USERAGENT])
          useragent = conn->allocptr.uagent;

        result =
          Curl_add_bufferf(req_buffer,
                           "CONNECT %s HTTP/%s\r\n"
                           "%s"  /* Host: */
                           "%s"  /* Proxy-Authorization */
                           "%s"  /* User-Agent */
                           "%s", /* Proxy-Connection */
                           hostheader,
                           http,
                           host?host:"",
                           conn->allocptr.proxyuserpwd?
                           conn->allocptr.proxyuserpwd:"",
                           useragent,
                           proxyconn);

        if(host)
          free(host);
        free(hostheader);

        if(!result)
          result = Curl_add_custom_headers(conn, TRUE, req_buffer);

        if(!result)
          /* CRLF terminate the request */
          result = Curl_add_bufferf(req_buffer, "\r\n");

        if(!result) {
          /* Send the connect request to the proxy */
          /* BLOCKING */
          result =
            Curl_add_buffer_send(req_buffer, conn,
                                 &data->info.request_size, 0, sockindex);
        }
        req_buffer = NULL;
        if(result)
          failf(data, "Failed sending CONNECT to proxy");
      }

      Curl_add_buffer_free(req_buffer);
      if(result)
        return result;

      conn->tunnel_state[sockindex] = TUNNEL_CONNECT;
    } /* END CONNECT PHASE */

    check = Curl_timeleft(data, NULL, TRUE);
    if(check <= 0) {
      failf(data, "Proxy CONNECT aborted due to timeout");
      return CURLE_RECV_ERROR;
    }

    if(!blocking) {
      if(!Curl_conn_data_pending(conn, sockindex))
        /* return so we'll be called again polling-style */
        return CURLE_OK;
      else {
        DEBUGF(infof(data,
               "Read response immediately from proxy CONNECT\n"));
      }
    }

    /* at this point, the tunnel_connecting phase is over. */

    { /* READING RESPONSE PHASE */
      size_t nread;   /* total size read */
      int perline; /* count bytes per line */
      int keepon=TRUE;
      ssize_t gotbytes;
      char *ptr;
      char *line_start;

      ptr = data->state.buffer;
      line_start = ptr;

      nread = 0;
      perline = 0;

      while(nread < BUFSIZE && keepon && !error) {
        int writetype;

        if(Curl_pgrsUpdate(conn))
          return CURLE_ABORTED_BY_CALLBACK;

        if(ptr >= &data->state.buffer[BUFSIZE]) {
          failf(data, "CONNECT response too large!");
          return CURLE_RECV_ERROR;
        }

        check = Curl_timeleft(data, NULL, TRUE);
        if(check <= 0) {
          failf(data, "Proxy CONNECT aborted due to timeout");
          error = SELECT_TIMEOUT; /* already too little time */
          break;
        }

        /* Read one byte at a time to avoid a race condition. Wait at most one
           second before looping to ensure continuous pgrsUpdates. */
        result = Curl_read(conn, tunnelsocket, ptr, 1, &gotbytes);
        if(result == CURLE_AGAIN) {
          if(SOCKET_READABLE(tunnelsocket, check<1000L?check:1000) == -1) {
            error = SELECT_ERROR;
            failf(data, "Proxy CONNECT aborted due to select/poll error");
            break;
          }
          continue;
        }
        else if(result) {
          keepon = FALSE;
          break;
        }
        else if(gotbytes <= 0) {
          if(data->set.proxyauth && data->state.authproxy.avail) {
            /* proxy auth was requested and there was proxy auth available,
               then deem this as "mere" proxy disconnect */
            conn->bits.proxy_connect_closed = TRUE;
            infof(data, "Proxy CONNECT connection closed\n");
          }
          else {
            error = SELECT_ERROR;
            failf(data, "Proxy CONNECT aborted");
          }
          keepon = FALSE;
          break;
        }

        /* We got a byte of data */
        nread++;

        if(keepon > TRUE) {
          /* This means we are currently ignoring a response-body */

          nread = 0; /* make next read start over in the read buffer */
          ptr = data->state.buffer;
          if(cl) {
            /* A Content-Length based body: simply count down the counter
               and make sure to break out of the loop when we're done! */
            cl--;
            if(cl <= 0) {
              keepon = FALSE;
              break;
            }
          }
          else {
            /* chunked-encoded body, so we need to do the chunked dance
               properly to know when the end of the body is reached */
            CHUNKcode r;
            ssize_t tookcareof = 0;

            /* now parse the chunked piece of data so that we can
               properly tell when the stream ends */
            r = Curl_httpchunk_read(conn, ptr, 1, &tookcareof);
            if(r == CHUNKE_STOP) {
              /* we're done reading chunks! */
              infof(data, "chunk reading DONE\n");
              keepon = FALSE;
              /* we did the full CONNECT treatment, go COMPLETE */
              conn->tunnel_state[sockindex] = TUNNEL_COMPLETE;
            }
          }
          continue;
        }

        perline++; /* amount of bytes in this line so far */

        /* if this is not the end of a header line then continue */
        if(*ptr != 0x0a) {
          ptr++;
          continue;
        }

        /* convert from the network encoding */
        result = Curl_convert_from_network(data, line_start, perline);
        /* Curl_convert_from_network calls failf if unsuccessful */
        if(result)
          return result;

        /* output debug if that is requested */
        if(data->set.verbose)
          Curl_debug(data, CURLINFO_HEADER_IN,
                     line_start, (size_t)perline, conn);

        /* send the header to the callback */
        writetype = CLIENTWRITE_HEADER;
        if(data->set.include_header)
          writetype |= CLIENTWRITE_BODY;

        result = Curl_client_write(conn, writetype, line_start, perline);

        data->info.header_size += (long)perline;
        data->req.headerbytecount += (long)perline;

        if(result)
          return result;

        /* Newlines are CRLF, so the CR is ignored as the line isn't
           really terminated until the LF comes. Treat a following CR
           as end-of-headers as well.*/

        if(('\r' == line_start[0]) ||
           ('\n' == line_start[0])) {
          /* end of response-headers from the proxy */
          nread = 0; /* make next read start over in the read
                        buffer */
          ptr = data->state.buffer;
          if((407 == k->httpcode) && !data->state.authproblem) {
            /* If we get a 407 response code with content length
               when we have no auth problem, we must ignore the
               whole response-body */
            keepon = 2;

            if(cl) {
              infof(data, "Ignore %" CURL_FORMAT_CURL_OFF_T
                    " bytes of response-body\n", cl);
            }
            else if(chunked_encoding) {
              CHUNKcode r;

              infof(data, "Ignore chunked response-body\n");

              /* We set ignorebody true here since the chunked
                 decoder function will acknowledge that. Pay
                 attention so that this is cleared again when this
                 function returns! */
              k->ignorebody = TRUE;

              if(line_start[1] == '\n') {
                /* this can only be a LF if the letter at index 0
                   was a CR */
                line_start++;
              }

              /* now parse the chunked piece of data so that we can
                 properly tell when the stream ends */
              r = Curl_httpchunk_read(conn, line_start + 1, 1, &gotbytes);
              if(r == CHUNKE_STOP) {
                /* we're done reading chunks! */
                infof(data, "chunk reading DONE\n");
                keepon = FALSE;
                /* we did the full CONNECT treatment, go to
                   COMPLETE */
                conn->tunnel_state[sockindex] = TUNNEL_COMPLETE;
              }
            }
            else {
              /* without content-length or chunked encoding, we
                 can't keep the connection alive since the close is
                 the end signal so we bail out at once instead */
              keepon = FALSE;
            }
          }
          else
            keepon = FALSE;
          /* we did the full CONNECT treatment, go to COMPLETE */
          conn->tunnel_state[sockindex] = TUNNEL_COMPLETE;
          continue;
        }

        line_start[perline] = 0; /* zero terminate the buffer */
        if((checkprefix("WWW-Authenticate:", line_start) &&
            (401 == k->httpcode)) ||
           (checkprefix("Proxy-authenticate:", line_start) &&
            (407 == k->httpcode))) {

          bool proxy = (k->httpcode == 407) ? TRUE : FALSE;
          char *auth = Curl_copy_header_value(line_start);
          if(!auth)
            return CURLE_OUT_OF_MEMORY;

          result = Curl_http_input_auth(conn, proxy, auth);

          free(auth);

          if(result)
            return result;
        }
        else if(checkprefix("Content-Length:", line_start)) {
          if(k->httpcode/100 == 2) {
            /* A server MUST NOT send any Transfer-Encoding or
               Content-Length header fields in a 2xx (Successful)
               response to CONNECT. (RFC 7231 section 4.3.6) */
            failf(data, "Content-Length: in %03d response",
                  k->httpcode);
            return CURLE_RECV_ERROR;
          }

          cl = curlx_strtoofft(line_start +
                               strlen("Content-Length:"), NULL, 10);
        }
        else if(Curl_compareheader(line_start, "Connection:", "close"))
          closeConnection = TRUE;
        else if(Curl_compareheader(line_start,
                                   "Transfer-Encoding:",
                                   "chunked")) {
          if(k->httpcode/100 == 2) {
            /* A server MUST NOT send any Transfer-Encoding or
               Content-Length header fields in a 2xx (Successful)
               response to CONNECT. (RFC 7231 section 4.3.6) */
            failf(data, "Transfer-Encoding: in %03d response", k->httpcode);
            return CURLE_RECV_ERROR;
          }
          infof(data, "CONNECT responded chunked\n");
          chunked_encoding = TRUE;
          /* init our chunky engine */
          Curl_httpchunk_init(conn);
        }
        else if(Curl_compareheader(line_start, "Proxy-Connection:", "close"))
          closeConnection = TRUE;
        else if(2 == sscanf(line_start, "HTTP/1.%d %d",
                            &subversion,
                            &k->httpcode)) {
          /* store the HTTP code from the proxy */
          data->info.httpproxycode = k->httpcode;
        }

        perline = 0; /* line starts over here */
        ptr = data->state.buffer;
        line_start = ptr;
      } /* while there's buffer left and loop is requested */

      if(Curl_pgrsUpdate(conn))
        return CURLE_ABORTED_BY_CALLBACK;

      if(error)
        return CURLE_RECV_ERROR;

      if(data->info.httpproxycode != 200) {
        /* Deal with the possibly already received authenticate
           headers. 'newurl' is set to a new URL if we must loop. */
        result = Curl_http_auth_act(conn);
        if(result)
          return result;

        if(conn->bits.close)
          /* the connection has been marked for closure, most likely in the
             Curl_http_auth_act() function and thus we can kill it at once
             below */
          closeConnection = TRUE;
      }

      if(closeConnection && data->req.newurl) {
        /* Connection closed by server. Don't use it anymore */
        Curl_closesocket(conn, conn->sock[sockindex]);
        conn->sock[sockindex] = CURL_SOCKET_BAD;
        break;
      }
    } /* END READING RESPONSE PHASE */

    /* If we are supposed to continue and request a new URL, which basically
     * means the HTTP authentication is still going on so if the tunnel
     * is complete we start over in INIT state */
    if(data->req.newurl &&
       (TUNNEL_COMPLETE == conn->tunnel_state[sockindex])) {
      conn->tunnel_state[sockindex] = TUNNEL_INIT;
      infof(data, "TUNNEL_STATE switched to: %d\n",
            conn->tunnel_state[sockindex]);
    }

  } while(data->req.newurl);

  if(200 != data->req.httpcode) {
    if(closeConnection && data->req.newurl) {
      conn->bits.proxy_connect_closed = TRUE;
      infof(data, "Connect me again please\n");
    }
    else {
      free(data->req.newurl);
      data->req.newurl = NULL;
      /* failure, close this connection to avoid re-use */
      streamclose(conn, "proxy CONNECT failure");
      Curl_closesocket(conn, conn->sock[sockindex]);
      conn->sock[sockindex] = CURL_SOCKET_BAD;
    }

    /* to back to init state */
    conn->tunnel_state[sockindex] = TUNNEL_INIT;

    if(conn->bits.proxy_connect_closed)
      /* this is not an error, just part of the connection negotiation */
      return CURLE_OK;
    else {
      failf(data, "Received HTTP code %d from proxy after CONNECT",
            data->req.httpcode);
      return CURLE_RECV_ERROR;
    }
  }

  conn->tunnel_state[sockindex] = TUNNEL_COMPLETE;

  /* If a proxy-authorization header was used for the proxy, then we should
     make sure that it isn't accidentally used for the document request
     after we've connected. So let's free and clear it here. */
  Curl_safefree(conn->allocptr.proxyuserpwd);
  conn->allocptr.proxyuserpwd = NULL;

  data->state.authproxy.done = TRUE;

  infof(data, "Proxy replied OK to CONNECT request\n");
  data->req.ignorebody = FALSE; /* put it (back) to non-ignore state */
  conn->bits.rewindaftersend = FALSE; /* make sure this isn't set for the
                                         document request  */
  return CURLE_OK;
}
#endif /* CURL_DISABLE_PROXY */
