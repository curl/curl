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

#ifndef CURL_DISABLE_PROXY

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "bufq.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "select.h"
#include "cfilters.h"
#include "connect.h"
#include "socks.h"
#include "curlx/inet_pton.h"

/* for the (SOCKS) connect state machine */
enum socks_state_t {
  SOCKS_ST_INIT,
  /* SOCKS Version 4 states */
  SOCKS4_ST_START,
  SOCKS4_ST_RESOLVING,
  SOCKS4_ST_SEND,
  SOCKS4_ST_RECV,
  /* SOCKS Version 5 states */
  SOCKS5_ST_START,
  SOCKS5_ST_REQ0_SEND,
  SOCKS5_ST_RESP0_RECV, /* set up read */
  SOCKS5_ST_GSSAPI_INIT,
  SOCKS5_ST_AUTH_INIT, /* setup outgoing auth buffer */
  SOCKS5_ST_AUTH_SEND, /* send auth */
  SOCKS5_ST_AUTH_RECV, /* read auth response */
  SOCKS5_ST_REQ1_INIT,  /* init SOCKS "request" */
  SOCKS5_ST_RESOLVING,
  SOCKS5_ST_REQ1_SEND,
  SOCKS5_ST_RESP1_RECV,
  /* Terminal states, all SOCKS versions */
  SOCKS_ST_SUCCESS,
  SOCKS_ST_FAILED
};

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
static const char * const cf_socks_statename[] = {
  "SOCKS_INIT",
  "SOCKS4_START",
  "SOCKS4_RESOLVING",
  "SOCKS4_SEND",
  "SOCKS4_RECV",
  "SOCKS5_START",
  "SOCKS5_REQ0_SEND",
  "SOCKS5_RESP0_RECV",
  "SOCKS5_GSSAPI_INIT",
  "SOCKS5_AUTH_INIT",
  "SOCKS5_AUTH_SEND",
  "SOCKS5_AUTH_RECV",
  "SOCKS5_REQ1_INIT",
  "SOCKS5_RESOLVING",
  "SOCKS5_REQ1_SEND",
  "SOCKS5_RESP1_RECV",
  "SOCKS_SUCCESS",
  "SOCKS_FAILED"
};
#endif

#define SOCKS_CHUNK_SIZE    1024
#define SOCKS_CHUNKS        1


struct socks_state {
  enum socks_state_t state;
  struct bufq iobuf;
  const char *hostname;
  int remote_port;
  const char *proxy_user;
  const char *proxy_password;
  CURLproxycode presult;
  unsigned char version;
  BIT(resolve_local);
  BIT(start_resolving);
  BIT(socks4a);
};

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior. Only used by the SOCKS GSSAPI functions.
 */
CURLcode Curl_blockread_all(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            char *buf,             /* store read data here */
                            size_t blen,           /* space in buf */
                            size_t *pnread)        /* amount bytes read */
{
  size_t nread = 0;
  CURLcode result;

  *pnread = 0;
  for(;;) {
    timediff_t timeout_ms = Curl_timeleft_ms(data);
    if(timeout_ms < 0) {
      /* we already got the timeout */
      return CURLE_OPERATION_TIMEDOUT;
    }
    if(!timeout_ms)
      timeout_ms = TIMEDIFF_T_MAX;
    if(SOCKET_READABLE(cf->conn->sock[cf->sockindex], timeout_ms) <= 0)
      return CURLE_OPERATION_TIMEDOUT;
    result = Curl_conn_cf_recv(cf->next, data, buf, blen, &nread);
    if(result == CURLE_AGAIN)
      continue;
    else if(result)
      return result;

    if(blen == nread) {
      *pnread += nread;
      return CURLE_OK;
    }
    if(!nread) /* EOF */
      return CURLE_RECV_ERROR;

    buf += nread;
    blen -= nread;
    *pnread += nread;
  }
}
#endif

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
#define sxstate(x, c, d, y) socksstate(x, c, d, y, __LINE__)
#else
#define sxstate(x, c, d, y) socksstate(x, c, d, y)
#endif

/* always use this function to change state, to make debugging easier */
static void socksstate(struct socks_state *sx,
                       struct Curl_cfilter *cf,
                       struct Curl_easy *data,
                       enum socks_state_t state
#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
                       , int lineno
#endif
)
{
  enum socks_state_t oldstate = sx->state;

  if(oldstate == state)
    /* do not bother when the new state is the same as the old state */
    return;

  sx->state = state;

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
  CURL_TRC_CF(data, cf, "[%s] -> [%s] (line %d)",
              cf_socks_statename[oldstate],
              cf_socks_statename[sx->state], lineno);
#else
  (void)cf;
  (void)data;
#endif
}

static CURLproxycode socks_failed(struct socks_state *sx,
                                  struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  CURLproxycode presult)
{
  sxstate(sx, cf, data, SOCKS_ST_FAILED);
  sx->presult = presult;
  return presult;
}

static CURLproxycode socks_flush(struct socks_state *sx,
                                 struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  CURLcode result;
  size_t nwritten;

  *done = FALSE;
  while(!Curl_bufq_is_empty(&sx->iobuf)) {
    result = Curl_cf_send_bufq(cf->next, data, &sx->iobuf, NULL, 0,
                               &nwritten);
    if(result == CURLE_AGAIN)
      return CURLPX_OK;
    else if(result) {
      failf(data, "Failed to send SOCKS request: %s",
            curl_easy_strerror(result));
      return socks_failed(sx, cf, data, CURLPX_SEND_CONNECT);
    }
  }
  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks_recv(struct socks_state *sx,
                                struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                size_t min_bytes,
                                bool *done)
{
  CURLcode result;
  size_t nread;

  *done = FALSE;
  while(Curl_bufq_len(&sx->iobuf) < min_bytes) {
    result = Curl_cf_recv_bufq(cf->next, data, &sx->iobuf,
                               min_bytes - Curl_bufq_len(&sx->iobuf),
                               &nread);
    if(result == CURLE_AGAIN)
      return CURLPX_OK;
    else if(result) {
      failf(data, "Failed to receive SOCKS response: %s",
            curl_easy_strerror(result));
      return CURLPX_RECV_CONNECT;
    }
    else if(!nread) { /* EOF */
      if(Curl_bufq_len(&sx->iobuf) < min_bytes) {
        failf(data, "Failed to receive SOCKS response, "
              "proxy closed connection");
        return CURLPX_RECV_CONNECT;
      }
      break;
    }
  }
  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks4_req_add_hd(struct socks_state *sx,
                                       struct Curl_easy *data)
{
  unsigned char buf[4];
  size_t nwritten;
  CURLcode result;

  (void)data;
  buf[0] = 4; /* version (SOCKS4) */
  buf[1] = 1; /* connect */
  buf[2] = (unsigned char)((sx->remote_port >> 8) & 0xffu); /* MSB */
  buf[3] = (unsigned char)(sx->remote_port & 0xffu);        /* LSB */

  result = Curl_bufq_write(&sx->iobuf, buf, 4, &nwritten);
  if(result || (nwritten != 4))
    return CURLPX_SEND_REQUEST;
  return CURLPX_OK;
}

static CURLproxycode socks4_req_add_user(struct socks_state *sx,
                                         struct Curl_easy *data)
{
  CURLcode result;
  size_t nwritten;

  if(sx->proxy_user) {
    size_t plen = strlen(sx->proxy_user);
    if(plen > 255) {
      /* there is no real size limit to this field in the protocol, but
         SOCKS5 limits the proxy user field to 255 bytes and it seems likely
         that a longer field is either a mistake or malicious input */
      failf(data, "Too long SOCKS proxy username");
      return CURLPX_LONG_USER;
    }
    /* add proxy name WITH trailing zero */
    result = Curl_bufq_cwrite(&sx->iobuf, sx->proxy_user, plen + 1,
                              &nwritten);
    if(result || (nwritten != (plen + 1)))
      return CURLPX_SEND_REQUEST;
  }
  else {
    /* empty username */
    unsigned char b = 0;
    result = Curl_bufq_write(&sx->iobuf, &b, 1, &nwritten);
    if(result || (nwritten != 1))
      return CURLPX_SEND_REQUEST;
  }
  return CURLPX_OK;
}

static CURLproxycode socks4_resolving(struct socks_state *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  struct Curl_dns_entry *dns = NULL;
  struct Curl_addrinfo *hp = NULL;
  CURLcode result;
  size_t nwritten;

  *done = FALSE;
  if(sx->start_resolving) {
    /* need to resolve hostname to add destination address */
    sx->start_resolving = FALSE;
    DEBUGASSERT(sx->hostname && *sx->hostname);

    result = Curl_resolv(data, sx->hostname, sx->remote_port,
                         cf->conn->ip_version, TRUE, &dns);
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "SOCKS4 non-blocking resolve of %s", sx->hostname);
      return CURLPX_OK;
    }
    else if(result)
      return CURLPX_RESOLVE_HOST;
  }
  else {
    /* check if we have the name resolved by now */
    result = Curl_resolv_check(data, &dns);
    if(!result && !dns)
      return CURLPX_OK;
  }

  if(result || !dns) {
    failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.", sx->hostname);
    return CURLPX_RESOLVE_HOST;
  }

  /*
   * We cannot use 'hostent' as a struct that Curl_resolv() returns. It
   * returns a Curl_addrinfo pointer that may not always look the same.
   */
  /* scan for the first IPv4 address */
  hp = dns->addr;
  while(hp && (hp->ai_family != AF_INET))
    hp = hp->ai_next;

  if(hp) {
    struct sockaddr_in *saddr_in;
    char ipbuf[64];

    Curl_printable_address(hp, ipbuf, sizeof(ipbuf));
    CURL_TRC_CF(data, cf, "SOCKS4 connect to IPv4 %s (locally resolved)",
                ipbuf);

    saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
    result = Curl_bufq_write(&sx->iobuf,
                             (unsigned char *)&saddr_in->sin_addr.s_addr, 4,
                             &nwritten);

    Curl_resolv_unlink(data, &dns); /* not used anymore from now on */
    if(result || (nwritten != 4))
      return CURLPX_SEND_REQUEST;
  }
  else {
    failf(data, "SOCKS4 connection to %s not supported", sx->hostname);
    return CURLPX_RESOLVE_HOST;
  }

  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks4_check_resp(struct socks_state *sx,
                                       struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  const unsigned char *resp;
  size_t rlen;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 8) {
    failf(data, "SOCKS4 reply is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  DEBUGASSERT(rlen == 8);
  /*
   * Response format
   *
   *     +----+----+----+----+----+----+----+----+
   *     | VN | CD | DSTPORT |      DSTIP        |
   *     +----+----+----+----+----+----+----+----+
   * # of bytes:  1    1      2              4
   *
   * VN is the version of the reply code and should be 0. CD is the result
   * code with one of the following values:
   *
   * 90: request granted
   * 91: request rejected or failed
   * 92: request rejected because SOCKS server cannot connect to
   *     identd on the client
   * 93: request rejected because the client program and identd
   *     report different user-ids
   */

  /* wrong version ? */
  if(resp[0]) {
    failf(data, "SOCKS4 reply has wrong version, version should be 0.");
    return CURLPX_BAD_VERSION;
  }

  /* Result */
  switch(resp[1]) {
  case 90:
    CURL_TRC_CF(data, cf, "SOCKS4%s request granted.", sx->socks4a ? "a" : "");
    Curl_bufq_skip(&sx->iobuf, 8);
    return CURLPX_OK;
  case 91:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected or failed.",
          resp[4], resp[5], resp[6], resp[7],
          ((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_REQUEST_FAILED;
  case 92:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          resp[4], resp[5], resp[6], resp[7],
          ((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_IDENTD;
  case 93:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          resp[4], resp[5], resp[6], resp[7],
          ((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_IDENTD_DIFFER;
  default:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", Unknown.",
          resp[4], resp[5], resp[6], resp[7],
          ((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_UNKNOWN_FAIL;
  }
}

/*
 * This function logs in to a SOCKS4 proxy and sends the specifics to the final
 * destination server.
 *
 * Reference :
 *   https://www.openssh.com/txt/socks4.protocol
 *
 * Note :
 *   Set protocol4a=true for  "SOCKS 4A (Simple Extension to SOCKS 4 Protocol)"
 *   Nonsupport "Identification Protocol (RFC1413)"
 */
static CURLproxycode socks4_connect(struct Curl_cfilter *cf,
                                    struct socks_state *sx,
                                    struct Curl_easy *data)
{
  size_t nwritten;
  CURLproxycode presult;
  CURLcode result;
  bool done;

process_state:
  switch(sx->state) {
  case SOCKS_ST_INIT:
    sx->version = 4;
    sxstate(sx, cf, data, SOCKS4_ST_START);
    FALLTHROUGH();

  case SOCKS4_ST_START:
    Curl_bufq_reset(&sx->iobuf);
    sx->start_resolving = FALSE;
    sx->socks4a = (cf->conn->socks_proxy.proxytype == CURLPROXY_SOCKS4A);
    sx->resolve_local = !sx->socks4a;
    sx->presult = CURLPX_OK;

    /* SOCKS4 can only do IPv4, insist! */
    cf->conn->ip_version = CURL_IPRESOLVE_V4;
    CURL_TRC_CF(data, cf, "SOCKS4%s communication to%s %s:%d",
                sx->socks4a ? "a" : "",
                cf->conn->bits.httpproxy ? " HTTP proxy" : "",
                sx->hostname, sx->remote_port);

    /*
     * Compose socks4 request
     *
     * Request format
     *
     *     +----+----+----+----+----+----+----+----+----+----+....+----+
     *     | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
     *     +----+----+----+----+----+----+----+----+----+----+....+----+
     * # of bytes:  1    1      2              4           variable       1
     */
    presult = socks4_req_add_hd(sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);

    /* DNS resolve only for SOCKS4, not SOCKS4a */
    if(!sx->resolve_local) {
      /* socks4a, not resolving locally, sends the hostname.
       * add an invalid address + user + hostname */
      unsigned char buf[4] = { 0, 0, 0, 1 };
      size_t hlen = strlen(sx->hostname) + 1; /* including NUL */

      if(hlen > 255) {
        failf(data, "SOCKS4: too long hostname");
        return socks_failed(sx, cf, data, CURLPX_LONG_HOSTNAME);
      }
      result = Curl_bufq_write(&sx->iobuf, buf, 4, &nwritten);
      if(result || (nwritten != 4))
        return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
      presult = socks4_req_add_user(sx, data);
      if(presult)
        return socks_failed(sx, cf, data, presult);
      result = Curl_bufq_cwrite(&sx->iobuf, sx->hostname, hlen, &nwritten);
      if(result || (nwritten != hlen))
        return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
      /* request complete */
      sxstate(sx, cf, data, SOCKS4_ST_SEND);
      goto process_state;
    }
    sx->start_resolving = TRUE;
    sxstate(sx, cf, data, SOCKS4_ST_RESOLVING);
    FALLTHROUGH();

  case SOCKS4_ST_RESOLVING:
    presult = socks4_resolving(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    /* append user */
    presult = socks4_req_add_user(sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS4_ST_SEND);
    FALLTHROUGH();

  case SOCKS4_ST_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS4_ST_RECV);
    FALLTHROUGH();

  case SOCKS4_ST_RECV:
    /* Receive 8 byte response */
    presult = socks_recv(sx, cf, data, 8, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks4_check_resp(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS_ST_SUCCESS);
    FALLTHROUGH();

  case SOCKS_ST_SUCCESS:
    return CURLPX_OK;

  case SOCKS_ST_FAILED:
    DEBUGASSERT(sx->presult);
    return sx->presult;

  default:
    DEBUGASSERT(0);
    return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
  }
}

static CURLproxycode socks5_req0_init(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data)
{
  const unsigned char auth = data->set.socks5auth;
  unsigned char req[5]; /* version + len + 3 possible auth methods */
  unsigned char nauths;
  size_t req_len, nwritten;
  CURLcode result;

  (void)cf;
  /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
  if(!sx->resolve_local && strlen(sx->hostname) > 255) {
    failf(data, "SOCKS5: the destination hostname is too long to be "
          "resolved remotely by the proxy.");
    return CURLPX_LONG_HOSTNAME;
  }

  if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
    infof(data, "warning: unsupported value passed to "
          "CURLOPT_SOCKS5_AUTH: %u", auth);
  if(!(auth & CURLAUTH_BASIC))
    /* disable username/password auth */
    sx->proxy_user = NULL;

  req[0] = 5;   /* version */
  nauths = 1;
  req[1 + nauths] = 0;   /* 1. no authentication */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(auth & CURLAUTH_GSSAPI) {
    ++nauths;
    req[1 + nauths] = 1; /* GSS-API */
  }
#endif
  if(sx->proxy_user) {
    ++nauths;
    req[1 + nauths] = 2; /* username/password */
  }
  req[1] = nauths;
  req_len = 2 + nauths;

  result = Curl_bufq_write(&sx->iobuf, req, req_len, &nwritten);
  if(result || (nwritten != req_len))
    return CURLPX_SEND_REQUEST;
  return CURLPX_OK;
}

static CURLproxycode socks5_check_resp0(struct socks_state *sx,
                                        struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  const unsigned char *resp;
  unsigned char auth_mode;
  size_t rlen;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 2) {
    failf(data, "SOCKS5 initial reply is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  if(resp[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return CURLPX_BAD_VERSION;
  }

  auth_mode = resp[1];
  Curl_bufq_skip(&sx->iobuf, 2);

  switch(auth_mode) {
  case 0:
    /* DONE! No authentication needed. Send request. */
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    return CURLPX_OK;
  case 1:
    if(data->set.socks5auth & CURLAUTH_GSSAPI) {
      sxstate(sx, cf, data, SOCKS5_ST_GSSAPI_INIT);
      return CURLPX_OK;
    }
    failf(data,
          "SOCKS5 GSSAPI per-message authentication is not enabled.");
    return CURLPX_GSSAPI_PERMSG;
  case 2:
    /* regular name + password authentication */
    if(data->set.socks5auth & CURLAUTH_BASIC) {
      sxstate(sx, cf, data, SOCKS5_ST_AUTH_INIT);
      return CURLPX_OK;
    }
    failf(data, "BASIC authentication proposed but not enabled.");
    return CURLPX_NO_AUTH;
  case 255:
    failf(data, "No authentication method was acceptable.");
    return CURLPX_NO_AUTH;
  default:
    failf(data, "Unknown SOCKS5 mode attempted to be used by server.");
    return CURLPX_UNKNOWN_MODE;
  }
}

static CURLproxycode socks5_auth_init(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data)
{
  /* Needs username and password */
  size_t ulen = 0, plen = 0, nwritten;
  unsigned char buf[2];
  CURLcode result;

  if(sx->proxy_user && sx->proxy_password) {
    ulen = strlen(sx->proxy_user);
    plen = strlen(sx->proxy_password);
    /* the lengths must fit in a single byte */
    if(ulen > 255) {
      failf(data, "Excessive username length for proxy auth");
      return CURLPX_LONG_USER;
    }
    if(plen > 255) {
      failf(data, "Excessive password length for proxy auth");
      return CURLPX_LONG_PASSWD;
    }
  }

  /*   username/password request looks like
   * +----+------+----------+------+----------+
   * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
   * +----+------+----------+------+----------+
   * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
   * +----+------+----------+------+----------+
   */
  buf[0] = 1;    /* username/pw subnegotiation version */
  buf[1] = (unsigned char)ulen;
  result = Curl_bufq_write(&sx->iobuf, buf, 2, &nwritten);
  if(result || (nwritten != 2))
    return CURLPX_SEND_REQUEST;
  if(ulen) {
    result = Curl_bufq_cwrite(&sx->iobuf, sx->proxy_user, ulen, &nwritten);
    if(result || (nwritten != ulen))
      return CURLPX_SEND_REQUEST;
  }
  buf[0] = (unsigned char)plen;
  result = Curl_bufq_write(&sx->iobuf, buf, 1, &nwritten);
  if(result || (nwritten != 1))
    return CURLPX_SEND_REQUEST;
  if(plen) {
    result = Curl_bufq_cwrite(&sx->iobuf, sx->proxy_password, plen, &nwritten);
    if(result || (nwritten != plen))
      return CURLPX_SEND_REQUEST;
  }
  sxstate(sx, cf, data, SOCKS5_ST_AUTH_SEND);
  return CURLPX_OK;
}

static CURLproxycode socks5_check_auth_resp(struct socks_state *sx,
                                            struct Curl_cfilter *cf,
                                            struct Curl_easy *data)
{
  const unsigned char *resp;
  unsigned char auth_status;
  size_t rlen;

  (void)cf;
  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 2) {
    failf(data, "SOCKS5 sub-negotiation response incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  /* ignore the first (VER) byte */
  auth_status = resp[1];
  if(auth_status) {
    failf(data, "User was rejected by the SOCKS5 server (%d %d).",
          resp[0], resp[1]);
    return CURLPX_USER_REJECTED;
  }
  Curl_bufq_skip(&sx->iobuf, 2);
  return CURLPX_OK;
}

static CURLproxycode socks5_req1_init(struct socks_state *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  unsigned char req[5];
  unsigned char ipbuf[16];
  const unsigned char *destination;
  unsigned char desttype, destlen, hdlen;
  size_t nwritten;
  CURLcode result;

  req[0] = 5; /* version (SOCKS5) */
  req[1] = 1; /* connect */
  req[2] = 0; /* must be zero */
  if(sx->resolve_local) {
    /* rest of request is added after resolving */
    result = Curl_bufq_write(&sx->iobuf, req, 3, &nwritten);
    if(result || (nwritten != 3))
      return CURLPX_SEND_REQUEST;
    return CURLPX_OK;
  }

  /* remote resolving, send what type+addr/string to resolve */
#ifdef USE_IPV6
  if(cf->conn->bits.ipv6_ip) {
    desttype = 4;
    destination = ipbuf;
    destlen = 16;
    if(curlx_inet_pton(AF_INET6, sx->hostname, ipbuf) != 1)
      return CURLPX_BAD_ADDRESS_TYPE;
  }
  else
#endif
  if(curlx_inet_pton(AF_INET, sx->hostname, ipbuf) == 1) {
    desttype = 1;
    destination = ipbuf;
    destlen = 4;
  }
  else {
    const size_t hostname_len = strlen(sx->hostname);
    desttype = 3;
    destination = (const unsigned char *)sx->hostname;
    destlen = (unsigned char)hostname_len; /* one byte length */
  }

  req[3] = desttype;
  req[4] = destlen;
  hdlen = (desttype == 3) ? 5 : 4; /* no length byte for ip addresses */
  result = Curl_bufq_write(&sx->iobuf, req, hdlen, &nwritten);
  if(result || (nwritten != hdlen))
    return CURLPX_SEND_REQUEST;
  result = Curl_bufq_write(&sx->iobuf, destination, destlen, &nwritten);
  if(result || (nwritten != destlen))
    return CURLPX_SEND_REQUEST;
  /* PORT MSB+LSB */
  req[0] = (unsigned char)((sx->remote_port >> 8) & 0xff);
  req[1] = (unsigned char)(sx->remote_port & 0xff);
  result = Curl_bufq_write(&sx->iobuf, req, 2, &nwritten);
  if(result || (nwritten != 2))
    return CURLPX_SEND_REQUEST;
  CURL_TRC_CF(data, cf, "SOCKS5 connect to %s:%d (remotely resolved)",
              sx->hostname, sx->remote_port);
  return CURLPX_OK;
}

static CURLproxycode socks5_resolving(struct socks_state *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  struct Curl_dns_entry *dns = NULL;
  struct Curl_addrinfo *hp = NULL;
  char dest[MAX_IPADR_LEN];  /* printable address */
  const unsigned char *destination = NULL;
  unsigned char desttype = 1, destlen = 4;
  unsigned char req[2];
  CURLcode result;
  CURLproxycode presult = CURLPX_OK;
  size_t nwritten;

  *done = FALSE;
  if(sx->start_resolving) {
    /* need to resolve hostname to add destination address */
    sx->start_resolving = FALSE;
    DEBUGASSERT(sx->hostname && *sx->hostname);

    result = Curl_resolv(data, sx->hostname, sx->remote_port,
                         cf->conn->ip_version, TRUE, &dns);
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "SOCKS5 non-blocking resolve of %s", sx->hostname);
      return CURLPX_OK;
    }
    else if(result)
      return CURLPX_RESOLVE_HOST;
  }
  else {
    /* check if we have the name resolved by now */
    result = Curl_resolv_check(data, &dns);
    if(!result && !dns)
      return CURLPX_OK;
  }

  if(result || !dns) {
    failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.", sx->hostname);
    presult = CURLPX_RESOLVE_HOST;
    goto out;
  }

  if(dns)
    hp = dns->addr;
#ifdef USE_IPV6
  if(data->set.ipver != CURL_IPRESOLVE_WHATEVER) {
    int wanted_family = data->set.ipver == CURL_IPRESOLVE_V4 ?
      AF_INET : AF_INET6;
    /* scan for the first proper address */
    while(hp && (hp->ai_family != wanted_family))
      hp = hp->ai_next;
  }
#endif
  if(!hp) {
    failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.", sx->hostname);
    presult = CURLPX_RESOLVE_HOST;
    goto out;
  }

  Curl_printable_address(hp, dest, sizeof(dest));

  if(hp->ai_family == AF_INET) {
    struct sockaddr_in *saddr_in;
    desttype = 1; /* ATYP: IPv4 = 1 */
    destlen = 4;
    saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
    destination = (const unsigned char *)&saddr_in->sin_addr.s_addr;
    CURL_TRC_CF(data, cf, "SOCKS5 connect to %s:%d (locally resolved)",
                dest, sx->remote_port);
  }
#ifdef USE_IPV6
  else if(hp->ai_family == AF_INET6) {
    struct sockaddr_in6 *saddr_in6;
    desttype = 4; /* ATYP: IPv6 = 4 */
    destlen = 16;
    saddr_in6 = (struct sockaddr_in6 *)(void *)hp->ai_addr;
    destination = (const unsigned char *)&saddr_in6->sin6_addr.s6_addr;
    CURL_TRC_CF(data, cf, "SOCKS5 connect to [%s]:%d (locally resolved)",
                dest, sx->remote_port);
  }
#endif

  if(!destination) {
    failf(data, "SOCKS5 connection to %s not supported", dest);
    presult = CURLPX_RESOLVE_HOST;
    goto out;
  }

  req[0] = desttype;
  result = Curl_bufq_write(&sx->iobuf, req, 1, &nwritten);
  if(result || (nwritten != 1)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }
  result = Curl_bufq_write(&sx->iobuf, destination, destlen, &nwritten);
  if(result || (nwritten != destlen)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }
  /* PORT MSB+LSB */
  req[0] = (unsigned char)((sx->remote_port >> 8) & 0xffu);
  req[1] = (unsigned char)(sx->remote_port & 0xffu);
  result = Curl_bufq_write(&sx->iobuf, req, 2, &nwritten);
  if(result || (nwritten != 2)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }

out:
  if(dns)
    Curl_resolv_unlink(data, &dns);
  *done = (presult == CURLPX_OK);
  return presult;
}

static CURLproxycode socks5_recv_resp1(struct socks_state *sx,
                                       struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
{
  const unsigned char *resp;
  size_t rlen, resp_len = 8; /* minimum response length */
  CURLproxycode presult;

  presult = socks_recv(sx, cf, data, resp_len, done);
  if(presult)
    return presult;
  else if(!*done)
    return CURLPX_OK;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < resp_len) {
    failf(data, "SOCKS5 response is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  /* Response packet includes BND.ADDR is variable length parameter by RFC
     1928, so the response packet MUST be read until the end to avoid errors
     at subsequent protocol level.

     +----+-----+-------+------+----------+----------+
     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  | X'00' |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+

     ATYP:
     o  IP v4 address: X'01', BND.ADDR = 4 byte
     o  domain name:   X'03', BND.ADDR = [ 1 byte length, string ]
     o  IP v6 address: X'04', BND.ADDR = 16 byte
  */
  if(resp[0] != 5) { /* version */
    failf(data, "SOCKS5 reply has wrong version, version should be 5.");
    return CURLPX_BAD_VERSION;
  }
  else if(resp[1]) { /* Anything besides 0 is an error */
    CURLproxycode rc = CURLPX_REPLY_UNASSIGNED;
    int code = resp[1];
    failf(data, "cannot complete SOCKS5 connection to %s. (%d)",
          sx->hostname, code);
    if(code < 9) {
      /* RFC 1928 section 6 lists: */
      static const CURLproxycode lookup[] = {
        CURLPX_OK,
        CURLPX_REPLY_GENERAL_SERVER_FAILURE,
        CURLPX_REPLY_NOT_ALLOWED,
        CURLPX_REPLY_NETWORK_UNREACHABLE,
        CURLPX_REPLY_HOST_UNREACHABLE,
        CURLPX_REPLY_CONNECTION_REFUSED,
        CURLPX_REPLY_TTL_EXPIRED,
        CURLPX_REPLY_COMMAND_NOT_SUPPORTED,
        CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
      };
      rc = lookup[code];
    }
    return rc;
  }

  /* Calculate real packet size */
  switch(resp[3]) {
  case 1: /* IPv4 */
    resp_len = 4 + 4 + 2;
    break;
  case 3: /* domain name */
    resp_len = 4 + 1 + resp[4] + 2; /* header, var length, var bytes, port */
    break;
  case 4: /* IPv6 */
    resp_len = 4 + 16 + 2;
    break;
  default:
    failf(data, "SOCKS5 reply has wrong address type.");
    return CURLPX_BAD_ADDRESS_TYPE;
  }

  /* receive the rest of the response */
  presult = socks_recv(sx, cf, data, resp_len, done);
  if(presult)
    return presult;
  else if(!*done)
    return CURLPX_OK;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < resp_len) {
    failf(data, "SOCKS5 response is incomplete.");
    return CURLPX_RECV_CONNECT;
  }
  /* got it all */
  *done = TRUE;
  return CURLPX_OK;
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
static CURLproxycode socks5_connect(struct Curl_cfilter *cf,
                                    struct socks_state *sx,
                                    struct Curl_easy *data)
{
  CURLproxycode presult;
  bool done;

process_state:
  switch(sx->state) {
  case SOCKS_ST_INIT:
    sx->version = 5;
    sx->resolve_local = (cf->conn->socks_proxy.proxytype == CURLPROXY_SOCKS5);
    sxstate(sx, cf, data, SOCKS5_ST_START);
    FALLTHROUGH();

  case SOCKS5_ST_START:
    if(cf->conn->bits.httpproxy)
      CURL_TRC_CF(data, cf, "SOCKS5: connecting to HTTP proxy %s port %d",
                  sx->hostname, sx->remote_port);
    presult = socks5_req0_init(cf, sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS5_ST_REQ0_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_REQ0_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    /* done sending! */
    sxstate(sx, cf, data, SOCKS5_ST_RESP0_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_RESP0_RECV:
    presult = socks_recv(sx, cf, data, 2, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks5_check_resp0(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    /* socks5_check_resp0() sets next socks state */
    goto process_state;

  case SOCKS5_ST_GSSAPI_INIT: {
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    /* GSSAPI stuff done non-blocking */
    CURLcode result = Curl_SOCKS5_gssapi_negotiate(cf, data);
    if(result) {
      failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
      return CURLPX_GSSAPI;
    }
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    goto process_state;
#else
    failf(data,
          "SOCKS5 GSSAPI per-message authentication is not supported.");
    return socks_failed(sx, cf, data, CURLPX_GSSAPI_PERMSG);
#endif
  }

  case SOCKS5_ST_AUTH_INIT:
    presult = socks5_auth_init(cf, sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS5_ST_AUTH_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_AUTH_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS5_ST_AUTH_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_AUTH_RECV:
    presult = socks_recv(sx, cf, data, 2, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks5_check_auth_resp(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    /* Everything is good so far, user was authenticated! */
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    FALLTHROUGH();

  case SOCKS5_ST_REQ1_INIT:
    presult = socks5_req1_init(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!sx->resolve_local) {
      /* we do not resolve, request is complete */
      sxstate(sx, cf, data, SOCKS5_ST_REQ1_SEND);
      goto process_state;
    }
    sx->start_resolving = TRUE;
    sxstate(sx, cf, data, SOCKS5_ST_RESOLVING);
    FALLTHROUGH();

  case SOCKS5_ST_RESOLVING:
    presult = socks5_resolving(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_REQ1_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(cf->conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sxstate(sx, cf, data, SOCKS5_ST_RESP1_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_RESP1_RECV:
    presult = socks5_recv_resp1(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    CURL_TRC_CF(data, cf, "SOCKS5 request granted.");
    sxstate(sx, cf, data, SOCKS_ST_SUCCESS);
    FALLTHROUGH();

  case SOCKS_ST_SUCCESS:
    return CURLPX_OK;

  case SOCKS_ST_FAILED:
    DEBUGASSERT(sx->presult);
    return sx->presult;

  default:
    DEBUGASSERT(0);
    return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
  }
}

static void socks_proxy_cf_free(struct Curl_cfilter *cf)
{
  struct socks_state *sxstate = cf->ctx;
  if(sxstate) {
    Curl_bufq_free(&sxstate->iobuf);
    curlx_free(sxstate);
    cf->ctx = NULL;
  }
}

/* After a TCP connection to the proxy has been verified, this function does
   the next magic steps. If 'done' is not set TRUE, it is not done yet and
   must be called again.

   Note: this function's sub-functions call failf()

*/
static CURLcode socks_proxy_cf_connect(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
{
  CURLcode result;
  struct connectdata *conn = cf->conn;
  int sockindex = cf->sockindex;
  struct socks_state *sx = cf->ctx;
  CURLproxycode pxresult = CURLPX_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf->next->cft->do_connect(cf->next, data, done);
  if(result || !*done)
    return result;

  if(!sx) {
    cf->ctx = sx = curlx_calloc(1, sizeof(*sx));
    if(!sx) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }

    /* for the secondary socket (FTP), use the "connect to host"
     * but ignore the "connect to port" (use the secondary port)
     */
    sx->hostname =
      conn->bits.httpproxy ?
      conn->http_proxy.host.name :
      conn->bits.conn_to_host ?
      conn->conn_to_host.name :
      sockindex == SECONDARYSOCKET ?
      conn->secondaryhostname : conn->host.name;
    sx->remote_port =
      conn->bits.httpproxy ? (int)conn->http_proxy.port :
      sockindex == SECONDARYSOCKET ? conn->secondary_port :
      conn->bits.conn_to_port ? conn->conn_to_port :
      conn->remote_port;
    sx->proxy_user = conn->socks_proxy.user;
    sx->proxy_password = conn->socks_proxy.passwd;
    Curl_bufq_init2(&sx->iobuf, SOCKS_CHUNK_SIZE, SOCKS_CHUNKS,
                    BUFQ_OPT_SOFT_LIMIT);
  }

  switch(conn->socks_proxy.proxytype) {
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    pxresult = socks5_connect(cf, sx, data);
    break;

  case CURLPROXY_SOCKS4:
  case CURLPROXY_SOCKS4A:
    pxresult = socks4_connect(cf, sx, data);
    break;

  default:
    failf(data, "unknown proxytype option given");
    result = CURLE_COULDNT_CONNECT;
    goto out;
  }

  if(pxresult) {
    result = CURLE_PROXY;
    data->info.pxcode = pxresult;
    goto out;
  }
  else if(sx->state != SOCKS_ST_SUCCESS)
    goto out;

#ifdef CURLVERBOSE
  if(Curl_trc_is_verbose(data)) {
    struct ip_quadruple ipquad;
    bool is_ipv6;
    if(!Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad))
      infof(data, "Opened %sSOCKS connection from %s port %u to %s port %u "
            "(via %s port %u)",
            (sockindex == SECONDARYSOCKET) ? "2nd " : "",
            ipquad.local_ip, ipquad.local_port,
            sx->hostname, sx->remote_port,
            ipquad.remote_ip, ipquad.remote_port);
    else
      infof(data, "Opened %sSOCKS connection",
            (sockindex == SECONDARYSOCKET) ? "2nd " : "");
  }
#endif
  socks_proxy_cf_free(cf);
  cf->connected = TRUE;

out:
  *done = (bool)cf->connected;
  return result;
}

static CURLcode socks_cf_adjust_pollset(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct socks_state *sx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!cf->connected && sx) {
    /* If we are not connected, the filter below is and has nothing
     * to wait on, we determine what to wait for. */
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);
    switch(sx->state) {
    case SOCKS4_ST_SEND:
    case SOCKS5_ST_REQ0_SEND:
    case SOCKS5_ST_AUTH_SEND:
    case SOCKS5_ST_REQ1_SEND:
      CURL_TRC_CF(data, cf, "adjust pollset out (%d)", sx->state);
      result = Curl_pollset_set_out_only(data, ps, sock);
      break;
    default:
      CURL_TRC_CF(data, cf, "adjust pollset in (%d)", sx->state);
      result = Curl_pollset_set_in_only(data, ps, sock);
      break;
    }
  }
  return result;
}

static void socks_proxy_cf_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{

  DEBUGASSERT(cf->next);
  cf->connected = FALSE;
  socks_proxy_cf_free(cf);
  cf->next->cft->do_close(cf->next, data);
}

static void socks_proxy_cf_destroy(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  (void)data;
  socks_proxy_cf_free(cf);
}

static CURLcode socks_cf_query(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int query, int *pres1, void *pres2)
{
  struct socks_state *sx = cf->ctx;

  switch(query) {
  case CF_QUERY_HOST_PORT:
    if(sx) {
      *pres1 = sx->remote_port;
      *((const char **)pres2) = sx->hostname;
      return CURLE_OK;
    }
    break;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_socks_proxy = {
  "SOCKS",
  CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
  0,
  socks_proxy_cf_destroy,
  socks_proxy_cf_connect,
  socks_proxy_cf_close,
  Curl_cf_def_shutdown,
  socks_cf_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  socks_cf_query,
};

CURLcode Curl_cf_socks_proxy_insert_after(struct Curl_cfilter *cf_at,
                                          struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  (void)data;
  result = Curl_cf_create(&cf, &Curl_cft_socks_proxy, NULL);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#endif /* CURL_DISABLE_PROXY */
