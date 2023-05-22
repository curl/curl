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

#if !defined(CURL_DISABLE_PROXY)

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "select.h"
#include "cfilters.h"
#include "connect.h"
#include "timeval.h"
#include "socks.h"
#include "multiif.h" /* for getsock macros */
#include "inet_pton.h"
#include "url.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* for the (SOCKS) connect state machine */
enum connect_t {
  CONNECT_INIT,
  CONNECT_SOCKS_INIT, /* 1 */
  CONNECT_SOCKS_SEND, /* 2 waiting to send more first data */
  CONNECT_SOCKS_READ_INIT, /* 3 set up read */
  CONNECT_SOCKS_READ, /* 4 read server response */
  CONNECT_GSSAPI_INIT, /* 5 */
  CONNECT_AUTH_INIT, /* 6 setup outgoing auth buffer */
  CONNECT_AUTH_SEND, /* 7 send auth */
  CONNECT_AUTH_READ, /* 8 read auth response */
  CONNECT_REQ_INIT,  /* 9 init SOCKS "request" */
  CONNECT_RESOLVING, /* 10 */
  CONNECT_RESOLVED,  /* 11 */
  CONNECT_RESOLVE_REMOTE, /* 12 */
  CONNECT_REQ_SEND,  /* 13 */
  CONNECT_REQ_SENDING, /* 14 */
  CONNECT_REQ_READ,  /* 15 */
  CONNECT_REQ_READ_MORE, /* 16 */
  CONNECT_DONE /* 17 connected fine to the remote or the SOCKS proxy */
};

struct socks_state {
  enum connect_t state;
  ssize_t outstanding;  /* send this many bytes more */
  unsigned char *outp; /* send from this pointer */

  const char *hostname;
  int remote_port;
  const char *proxy_user;
  const char *proxy_password;
};

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior. Only used by the SOCKS GSSAPI functions.
 */
int Curl_blockread_all(struct Curl_cfilter *cf,
                       struct Curl_easy *data,   /* transfer */
                       char *buf,                /* store read data here */
                       ssize_t buffersize,       /* max amount to read */
                       ssize_t *n)               /* amount bytes read */
{
  ssize_t nread = 0;
  ssize_t allread = 0;
  int result;
  CURLcode err = CURLE_OK;

  *n = 0;
  for(;;) {
    timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);
    if(timeout_ms < 0) {
      /* we already got the timeout */
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    if(!timeout_ms)
      timeout_ms = TIMEDIFF_T_MAX;
    if(SOCKET_READABLE(cf->conn->sock[cf->sockindex], timeout_ms) <= 0) {
      result = ~CURLE_OK;
      break;
    }
    nread = Curl_conn_cf_recv(cf->next, data, buf, buffersize, &err);
    if(nread <= 0) {
      result = err;
      if(CURLE_AGAIN == err)
        continue;
      if(err) {
        break;
      }
    }

    if(buffersize == nread) {
      allread += nread;
      *n = allread;
      result = CURLE_OK;
      break;
    }
    if(!nread) {
      result = ~CURLE_OK;
      break;
    }

    buffersize -= nread;
    buf += nread;
    allread += nread;
  }
  return result;
}
#endif

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
#define DEBUG_AND_VERBOSE
#define sxstate(x,d,y) socksstate(x,d,y, __LINE__)
#else
#define sxstate(x,d,y) socksstate(x,d,y)
#endif

/* always use this function to change state, to make debugging easier */
static void socksstate(struct socks_state *sx, struct Curl_easy *data,
                       enum connect_t state
#ifdef DEBUG_AND_VERBOSE
                       , int lineno
#endif
)
{
  enum connect_t oldstate = sx->state;
#ifdef DEBUG_AND_VERBOSE
  /* synced with the state list in urldata.h */
  static const char * const statename[] = {
    "INIT",
    "SOCKS_INIT",
    "SOCKS_SEND",
    "SOCKS_READ_INIT",
    "SOCKS_READ",
    "GSSAPI_INIT",
    "AUTH_INIT",
    "AUTH_SEND",
    "AUTH_READ",
    "REQ_INIT",
    "RESOLVING",
    "RESOLVED",
    "RESOLVE_REMOTE",
    "REQ_SEND",
    "REQ_SENDING",
    "REQ_READ",
    "REQ_READ_MORE",
    "DONE"
  };
#endif

  (void)data;
  if(oldstate == state)
    /* don't bother when the new state is the same as the old state */
    return;

  sx->state = state;

#ifdef DEBUG_AND_VERBOSE
  infof(data,
        "SXSTATE: %s => %s; line %d",
        statename[oldstate], statename[sx->state],
        lineno);
#endif
}

static CURLproxycode socks_state_send(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data,
                                      CURLproxycode failcode,
                                      const char *description)
{
  ssize_t nwritten;
  CURLcode result;

  nwritten = Curl_conn_cf_send(cf->next, data, (char *)sx->outp,
                               sx->outstanding, &result);
  if(nwritten <= 0) {
    if(CURLE_AGAIN == result) {
      return CURLPX_OK;
    }
    else if(CURLE_OK == result) {
      /* connection closed */
      failf(data, "connection to proxy closed");
      return CURLPX_CLOSED;
    }
    failf(data, "Failed to send %s: %s", description,
          curl_easy_strerror(result));
    return failcode;
  }
  DEBUGASSERT(sx->outstanding >= nwritten);
  /* not done, remain in state */
  sx->outstanding -= nwritten;
  sx->outp += nwritten;
  return CURLPX_OK;
}

static CURLproxycode socks_state_recv(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data,
                                      CURLproxycode failcode,
                                      const char *description)
{
  ssize_t nread;
  CURLcode result;

  nread = Curl_conn_cf_recv(cf->next, data, (char *)sx->outp,
                            sx->outstanding, &result);
  if(nread <= 0) {
    if(CURLE_AGAIN == result) {
      return CURLPX_OK;
    }
    else if(CURLE_OK == result) {
      /* connection closed */
      failf(data, "connection to proxy closed");
      return CURLPX_CLOSED;
    }
    failf(data, "SOCKS4: Failed receiving %s: %s", description,
          curl_easy_strerror(result));
    return failcode;
  }
  /* remain in reading state */
  DEBUGASSERT(sx->outstanding >= nread);
  sx->outstanding -= nread;
  sx->outp += nread;
  return CURLPX_OK;
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
static CURLproxycode do_SOCKS4(struct Curl_cfilter *cf,
                               struct socks_state *sx,
                               struct Curl_easy *data)
{
  struct connectdata *conn = cf->conn;
  const bool protocol4a =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS4A) ? TRUE : FALSE;
  unsigned char *socksreq = (unsigned char *)data->state.buffer;
  CURLcode result;
  CURLproxycode presult;
  struct Curl_dns_entry *dns = NULL;

  /* make sure that the buffer is at least 600 bytes */
  DEBUGASSERT(READBUFFER_MIN >= 600);

  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    /* SOCKS4 can only do IPv4, insist! */
    conn->ip_version = CURL_IPRESOLVE_V4;
    if(conn->bits.httpproxy)
      infof(data, "SOCKS4%s: connecting to HTTP proxy %s port %d",
            protocol4a ? "a" : "", sx->hostname, sx->remote_port);

    infof(data, "SOCKS4 communication to %s:%d",
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

    socksreq[0] = 4; /* version (SOCKS4) */
    socksreq[1] = 1; /* connect */
    socksreq[2] = (unsigned char)((sx->remote_port >> 8) & 0xff); /* MSB */
    socksreq[3] = (unsigned char)(sx->remote_port & 0xff);        /* LSB */

    /* DNS resolve only for SOCKS4, not SOCKS4a */
    if(!protocol4a) {
      enum resolve_t rc =
        Curl_resolv(data, sx->hostname, sx->remote_port, TRUE, &dns);

      if(rc == CURLRESOLV_ERROR)
        return CURLPX_RESOLVE_HOST;
      else if(rc == CURLRESOLV_PENDING) {
        sxstate(sx, data, CONNECT_RESOLVING);
        infof(data, "SOCKS4 non-blocking resolve of %s", sx->hostname);
        return CURLPX_OK;
      }
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }

    /* socks4a doesn't resolve anything locally */
    sxstate(sx, data, CONNECT_REQ_INIT);
    goto CONNECT_REQ_INIT;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    dns = Curl_fetch_addr(data, sx->hostname, (int)conn->port);

    if(dns) {
#ifdef CURLRES_ASYNCH
      data->state.async.dns = dns;
      data->state.async.done = TRUE;
#endif
      infof(data, "Hostname '%s' was found", sx->hostname);
      sxstate(sx, data, CONNECT_RESOLVED);
    }
    else {
      result = Curl_resolv_check(data, &dns);
      if(!dns) {
        if(result)
          return CURLPX_RESOLVE_HOST;
        return CURLPX_OK;
      }
    }
    /* FALLTHROUGH */
CONNECT_RESOLVED:
  case CONNECT_RESOLVED: {
    struct Curl_addrinfo *hp = NULL;
    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns) {
      hp = dns->addr;

      /* scan for the first IPv4 address */
      while(hp && (hp->ai_family != AF_INET))
        hp = hp->ai_next;

      if(hp) {
        struct sockaddr_in *saddr_in;
        char buf[64];
        Curl_printable_address(hp, buf, sizeof(buf));

        saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
        socksreq[4] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[0];
        socksreq[5] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[1];
        socksreq[6] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[2];
        socksreq[7] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[3];

        infof(data, "SOCKS4 connect to IPv4 %s (locally resolved)", buf);

        Curl_resolv_unlock(data, dns); /* not used anymore from now on */
      }
      else
        failf(data, "SOCKS4 connection to %s not supported", sx->hostname);
    }
    else
      failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
            sx->hostname);

    if(!hp)
      return CURLPX_RESOLVE_HOST;
  }
    /* FALLTHROUGH */
CONNECT_REQ_INIT:
  case CONNECT_REQ_INIT:
    /*
     * This is currently not supporting "Identification Protocol (RFC1413)".
     */
    socksreq[8] = 0; /* ensure empty userid is NUL-terminated */
    if(sx->proxy_user) {
      size_t plen = strlen(sx->proxy_user);
      if(plen >= (size_t)data->set.buffer_size - 8) {
        failf(data, "Too long SOCKS proxy user name, can't use");
        return CURLPX_LONG_USER;
      }
      /* copy the proxy name WITH trailing zero */
      memcpy(socksreq + 8, sx->proxy_user, plen + 1);
    }

    /*
     * Make connection
     */
    {
      size_t packetsize = 9 +
        strlen((char *)socksreq + 8); /* size including NUL */

      /* If SOCKS4a, set special invalid IP address 0.0.0.x */
      if(protocol4a) {
        size_t hostnamelen = 0;
        socksreq[4] = 0;
        socksreq[5] = 0;
        socksreq[6] = 0;
        socksreq[7] = 1;
        /* append hostname */
        hostnamelen = strlen(sx->hostname) + 1; /* length including NUL */
        if(hostnamelen <= 255)
          strcpy((char *)socksreq + packetsize, sx->hostname);
        else {
          failf(data, "SOCKS4: too long host name");
          return CURLPX_LONG_HOSTNAME;
        }
        packetsize += hostnamelen;
      }
      sx->outp = socksreq;
      sx->outstanding = packetsize;
      sxstate(sx, data, CONNECT_REQ_SENDING);
    }
    /* FALLTHROUGH */
  case CONNECT_REQ_SENDING:
    /* Send request */
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "SOCKS4 connect request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    /* done sending! */
    sx->outstanding = 8; /* receive data size */
    sx->outp = socksreq;
    sxstate(sx, data, CONNECT_SOCKS_READ);

    /* FALLTHROUGH */
  case CONNECT_SOCKS_READ:
    /* Receive response */
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                               "connect request ack");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_DONE);
    break;
  default: /* lots of unused states in SOCKS4 */
    break;
  }

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
  if(socksreq[0]) {
    failf(data,
          "SOCKS4 reply has wrong version, version should be 0.");
    return CURLPX_BAD_VERSION;
  }

  /* Result */
  switch(socksreq[1]) {
  case 90:
    infof(data, "SOCKS4%s request granted.", protocol4a?"a":"");
    break;
  case 91:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected or failed.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_REQUEST_FAILED;
  case 92:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_IDENTD;
  case 93:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_IDENTD_DIFFER;
  default:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", Unknown.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_UNKNOWN_FAIL;
  }

  return CURLPX_OK; /* Proxy was successful! */
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
static CURLproxycode do_SOCKS5(struct Curl_cfilter *cf,
                               struct socks_state *sx,
                               struct Curl_easy *data)
{
  /*
    According to the RFC1928, section "6.  Replies". This is what a SOCK5
    replies:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

    Where:

    o  VER    protocol version: X'05'
    o  REP    Reply field:
    o  X'00' succeeded
  */
  struct connectdata *conn = cf->conn;
  unsigned char *socksreq = (unsigned char *)data->state.buffer;
  char dest[256] = "unknown";  /* printable hostname:port */
  int idx;
  CURLcode result;
  CURLproxycode presult;
  bool socks5_resolve_local =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS5) ? TRUE : FALSE;
  const size_t hostname_len = strlen(sx->hostname);
  ssize_t len = 0;
  const unsigned char auth = data->set.socks5auth;
  bool allow_gssapi = FALSE;
  struct Curl_dns_entry *dns = NULL;

  DEBUGASSERT(auth & (CURLAUTH_BASIC | CURLAUTH_GSSAPI));
  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    if(conn->bits.httpproxy)
      infof(data, "SOCKS5: connecting to HTTP proxy %s port %d",
            sx->hostname, sx->remote_port);

    /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
    if(!socks5_resolve_local && hostname_len > 255) {
      infof(data, "SOCKS5: server resolving disabled for hostnames of "
            "length > 255 [actual len=%zu]", hostname_len);
      socks5_resolve_local = TRUE;
    }

    if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
      infof(data,
            "warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: %u",
            auth);
    if(!(auth & CURLAUTH_BASIC))
      /* disable username/password auth */
      sx->proxy_user = NULL;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(auth & CURLAUTH_GSSAPI)
      allow_gssapi = TRUE;
#endif

    idx = 0;
    socksreq[idx++] = 5;   /* version */
    idx++;                 /* number of authentication methods */
    socksreq[idx++] = 0;   /* no authentication */
    if(allow_gssapi)
      socksreq[idx++] = 1; /* GSS-API */
    if(sx->proxy_user)
      socksreq[idx++] = 2; /* username/password */
    /* write the number of authentication methods */
    socksreq[1] = (unsigned char) (idx - 2);

    sx->outp = socksreq;
    sx->outstanding = idx;
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "initial SOCKS5 request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_SOCKS_READ);
    goto CONNECT_SOCKS_READ_INIT;
  case CONNECT_SOCKS_SEND:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "initial SOCKS5 request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    /* FALLTHROUGH */
CONNECT_SOCKS_READ_INIT:
  case CONNECT_SOCKS_READ_INIT:
    sx->outstanding = 2; /* expect two bytes */
    sx->outp = socksreq; /* store it here */
    /* FALLTHROUGH */
  case CONNECT_SOCKS_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                               "initial SOCKS5 response");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    else if(socksreq[0] != 5) {
      failf(data, "Received invalid version in initial SOCKS5 response.");
      return CURLPX_BAD_VERSION;
    }
    else if(socksreq[1] == 0) {
      /* DONE! No authentication needed. Send request. */
      sxstate(sx, data, CONNECT_REQ_INIT);
      goto CONNECT_REQ_INIT;
    }
    else if(socksreq[1] == 2) {
      /* regular name + password authentication */
      sxstate(sx, data, CONNECT_AUTH_INIT);
      goto CONNECT_AUTH_INIT;
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    else if(allow_gssapi && (socksreq[1] == 1)) {
      sxstate(sx, data, CONNECT_GSSAPI_INIT);
      result = Curl_SOCKS5_gssapi_negotiate(cf, data);
      if(result) {
        failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
        return CURLPX_GSSAPI;
      }
    }
#endif
    else {
      /* error */
      if(!allow_gssapi && (socksreq[1] == 1)) {
        failf(data,
              "SOCKS5 GSSAPI per-message authentication is not supported.");
        return CURLPX_GSSAPI_PERMSG;
      }
      else if(socksreq[1] == 255) {
        failf(data, "No authentication method was acceptable.");
        return CURLPX_NO_AUTH;
      }
    }
    failf(data,
          "Undocumented SOCKS5 mode attempted to be used by server.");
    return CURLPX_UNKNOWN_MODE;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case CONNECT_GSSAPI_INIT:
    /* GSSAPI stuff done non-blocking */
    break;
#endif

  default: /* do nothing! */
    break;

CONNECT_AUTH_INIT:
  case CONNECT_AUTH_INIT: {
    /* Needs user name and password */
    size_t proxy_user_len, proxy_password_len;
    if(sx->proxy_user && sx->proxy_password) {
      proxy_user_len = strlen(sx->proxy_user);
      proxy_password_len = strlen(sx->proxy_password);
    }
    else {
      proxy_user_len = 0;
      proxy_password_len = 0;
    }

    /*   username/password request looks like
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */
    len = 0;
    socksreq[len++] = 1;    /* username/pw subnegotiation version */
    socksreq[len++] = (unsigned char) proxy_user_len;
    if(sx->proxy_user && proxy_user_len) {
      /* the length must fit in a single byte */
      if(proxy_user_len > 255) {
        failf(data, "Excessive user name length for proxy auth");
        return CURLPX_LONG_USER;
      }
      memcpy(socksreq + len, sx->proxy_user, proxy_user_len);
    }
    len += proxy_user_len;
    socksreq[len++] = (unsigned char) proxy_password_len;
    if(sx->proxy_password && proxy_password_len) {
      /* the length must fit in a single byte */
      if(proxy_password_len > 255) {
        failf(data, "Excessive password length for proxy auth");
        return CURLPX_LONG_PASSWD;
      }
      memcpy(socksreq + len, sx->proxy_password, proxy_password_len);
    }
    len += proxy_password_len;
    sxstate(sx, data, CONNECT_AUTH_SEND);
    sx->outstanding = len;
    sx->outp = socksreq;
  }
    /* FALLTHROUGH */
  case CONNECT_AUTH_SEND:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_AUTH,
                               "SOCKS5 sub-negotiation request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    sx->outp = socksreq;
    sx->outstanding = 2;
    sxstate(sx, data, CONNECT_AUTH_READ);
    /* FALLTHROUGH */
  case CONNECT_AUTH_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_AUTH,
                               "SOCKS5 sub-negotiation response");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    /* ignore the first (VER) byte */
    else if(socksreq[1]) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLPX_USER_REJECTED;
    }

    /* Everything is good so far, user was authenticated! */
    sxstate(sx, data, CONNECT_REQ_INIT);
    /* FALLTHROUGH */
CONNECT_REQ_INIT:
  case CONNECT_REQ_INIT:
    if(socks5_resolve_local) {
      enum resolve_t rc = Curl_resolv(data, sx->hostname, sx->remote_port,
                                      TRUE, &dns);

      if(rc == CURLRESOLV_ERROR)
        return CURLPX_RESOLVE_HOST;

      if(rc == CURLRESOLV_PENDING) {
        sxstate(sx, data, CONNECT_RESOLVING);
        return CURLPX_OK;
      }
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }
    goto CONNECT_RESOLVE_REMOTE;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    dns = Curl_fetch_addr(data, sx->hostname, sx->remote_port);

    if(dns) {
#ifdef CURLRES_ASYNCH
      data->state.async.dns = dns;
      data->state.async.done = TRUE;
#endif
      infof(data, "SOCKS5: hostname '%s' found", sx->hostname);
    }

    if(!dns) {
      result = Curl_resolv_check(data, &dns);
      if(!dns) {
        if(result)
          return CURLPX_RESOLVE_HOST;
        return CURLPX_OK;
      }
    }
    /* FALLTHROUGH */
CONNECT_RESOLVED:
  case CONNECT_RESOLVED: {
    struct Curl_addrinfo *hp = NULL;
    size_t destlen;
    if(dns)
      hp = dns->addr;
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            sx->hostname);
      return CURLPX_RESOLVE_HOST;
    }

    Curl_printable_address(hp, dest, sizeof(dest));
    destlen = strlen(dest);
    msnprintf(dest + destlen, sizeof(dest) - destlen, ":%d", sx->remote_port);

    len = 0;
    socksreq[len++] = 5; /* version (SOCKS5) */
    socksreq[len++] = 1; /* connect */
    socksreq[len++] = 0; /* must be zero */
    if(hp->ai_family == AF_INET) {
      int i;
      struct sockaddr_in *saddr_in;
      socksreq[len++] = 1; /* ATYP: IPv4 = 1 */

      saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
      for(i = 0; i < 4; i++) {
        socksreq[len++] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[i];
      }

      infof(data, "SOCKS5 connect to IPv4 %s (locally resolved)", dest);
    }
#ifdef ENABLE_IPV6
    else if(hp->ai_family == AF_INET6) {
      int i;
      struct sockaddr_in6 *saddr_in6;
      socksreq[len++] = 4; /* ATYP: IPv6 = 4 */

      saddr_in6 = (struct sockaddr_in6 *)(void *)hp->ai_addr;
      for(i = 0; i < 16; i++) {
        socksreq[len++] =
          ((unsigned char *)&saddr_in6->sin6_addr.s6_addr)[i];
      }

      infof(data, "SOCKS5 connect to IPv6 %s (locally resolved)", dest);
    }
#endif
    else {
      hp = NULL; /* fail! */
      failf(data, "SOCKS5 connection to %s not supported", dest);
    }

    Curl_resolv_unlock(data, dns); /* not used anymore from now on */
    goto CONNECT_REQ_SEND;
  }
CONNECT_RESOLVE_REMOTE:
  case CONNECT_RESOLVE_REMOTE:
    /* Authentication is complete, now specify destination to the proxy */
    len = 0;
    socksreq[len++] = 5; /* version (SOCKS5) */
    socksreq[len++] = 1; /* connect */
    socksreq[len++] = 0; /* must be zero */

    if(!socks5_resolve_local) {
      /* ATYP: domain name = 3,
         IPv6 == 4,
         IPv4 == 1 */
      unsigned char ip4[4];
#ifdef ENABLE_IPV6
      if(conn->bits.ipv6_ip) {
        char ip6[16];
        if(1 != Curl_inet_pton(AF_INET6, sx->hostname, ip6))
          return CURLPX_BAD_ADDRESS_TYPE;
        socksreq[len++] = 4;
        memcpy(&socksreq[len], ip6, sizeof(ip6));
        len += sizeof(ip6);
      }
      else
#endif
      if(1 == Curl_inet_pton(AF_INET, sx->hostname, ip4)) {
        socksreq[len++] = 1;
        memcpy(&socksreq[len], ip4, sizeof(ip4));
        len += sizeof(ip4);
      }
      else {
        socksreq[len++] = 3;
        socksreq[len++] = (char) hostname_len; /* one byte address length */
        memcpy(&socksreq[len], sx->hostname, hostname_len); /* w/o NULL */
        len += hostname_len;
      }
      infof(data, "SOCKS5 connect to %s:%d (remotely resolved)",
            sx->hostname, sx->remote_port);
    }
    /* FALLTHROUGH */

CONNECT_REQ_SEND:
  case CONNECT_REQ_SEND:
    /* PORT MSB */
    socksreq[len++] = (unsigned char)((sx->remote_port >> 8) & 0xff);
    /* PORT LSB */
    socksreq[len++] = (unsigned char)(sx->remote_port & 0xff);

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sx->outp = socksreq;
    sx->outstanding = len;
    sxstate(sx, data, CONNECT_REQ_SENDING);
    /* FALLTHROUGH */
  case CONNECT_REQ_SENDING:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_REQUEST,
                               "SOCKS5 connect request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in send state */
      return CURLPX_OK;
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sx->outstanding = 10; /* minimum packet size is 10 */
    sx->outp = socksreq;
    sxstate(sx, data, CONNECT_REQ_READ);
    /* FALLTHROUGH */
  case CONNECT_REQ_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_REQACK,
                               "SOCKS5 connect request ack");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    else if(socksreq[0] != 5) { /* version */
      failf(data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return CURLPX_BAD_VERSION;
    }
    else if(socksreq[1]) { /* Anything besides 0 is an error */
      CURLproxycode rc = CURLPX_REPLY_UNASSIGNED;
      int code = socksreq[1];
      failf(data, "Can't complete SOCKS5 connection to %s. (%d)",
            sx->hostname, (unsigned char)socksreq[1]);
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

    /* Fix: in general, returned BND.ADDR is variable length parameter by RFC
       1928, so the reply packet should be read until the end to avoid errors
       at subsequent protocol level.

       +----+-----+-------+------+----------+----------+
       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
       +----+-----+-------+------+----------+----------+
       | 1  |  1  | X'00' |  1   | Variable |    2     |
       +----+-----+-------+------+----------+----------+

       ATYP:
       o  IP v4 address: X'01', BND.ADDR = 4 byte
       o  domain name:  X'03', BND.ADDR = [ 1 byte length, string ]
       o  IP v6 address: X'04', BND.ADDR = 16 byte
    */

    /* Calculate real packet size */
    if(socksreq[3] == 3) {
      /* domain name */
      int addrlen = (int) socksreq[4];
      len = 5 + addrlen + 2;
    }
    else if(socksreq[3] == 4) {
      /* IPv6 */
      len = 4 + 16 + 2;
    }
    else if(socksreq[3] == 1) {
      len = 4 + 4 + 2;
    }
    else {
      failf(data, "SOCKS5 reply has wrong address type.");
      return CURLPX_BAD_ADDRESS_TYPE;
    }

    /* At this point we already read first 10 bytes */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(!conn->socks5_gssapi_enctype) {
      /* decrypt_gssapi_blockread already read the whole packet */
#endif
      if(len > 10) {
        sx->outstanding = len - 10; /* get the rest */
        sx->outp = &socksreq[10];
        sxstate(sx, data, CONNECT_REQ_READ_MORE);
      }
      else {
        sxstate(sx, data, CONNECT_DONE);
        break;
      }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    }
#endif
    /* FALLTHROUGH */
  case CONNECT_REQ_READ_MORE:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_ADDRESS,
                               "SOCKS5 connect request address");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_DONE);
  }
  infof(data, "SOCKS5 request granted.");

  return CURLPX_OK; /* Proxy was successful! */
}

static CURLcode connect_SOCKS(struct Curl_cfilter *cf,
                              struct socks_state *sxstate,
                              struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  CURLproxycode pxresult = CURLPX_OK;
  struct connectdata *conn = cf->conn;

  switch(conn->socks_proxy.proxytype) {
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    pxresult = do_SOCKS5(cf, sxstate, data);
    break;

  case CURLPROXY_SOCKS4:
  case CURLPROXY_SOCKS4A:
    pxresult = do_SOCKS4(cf, sxstate, data);
    break;

  default:
    failf(data, "unknown proxytype option given");
    result = CURLE_COULDNT_CONNECT;
  } /* switch proxytype */
  if(pxresult) {
    result = CURLE_PROXY;
    data->info.pxcode = pxresult;
  }

  return result;
}

static void socks_proxy_cf_free(struct Curl_cfilter *cf)
{
  struct socks_state *sxstate = cf->ctx;
  if(sxstate) {
    free(sxstate);
    cf->ctx = NULL;
  }
}

/* After a TCP connection to the proxy has been verified, this function does
   the next magic steps. If 'done' isn't set TRUE, it is not done yet and
   must be called again.

   Note: this function's sub-functions call failf()

*/
static CURLcode socks_proxy_cf_connect(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool blocking, bool *done)
{
  CURLcode result;
  struct connectdata *conn = cf->conn;
  int sockindex = cf->sockindex;
  struct socks_state *sx = cf->ctx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    return result;

  if(!sx) {
    sx = calloc(sizeof(*sx), 1);
    if(!sx)
      return CURLE_OUT_OF_MEMORY;
    cf->ctx = sx;
  }

  if(sx->state == CONNECT_INIT) {
    /* for the secondary socket (FTP), use the "connect to host"
     * but ignore the "connect to port" (use the secondary port)
     */
    sxstate(sx, data, CONNECT_SOCKS_INIT);
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
  }

  result = connect_SOCKS(cf, sx, data);
  if(!result && sx->state == CONNECT_DONE) {
    cf->connected = TRUE;
    Curl_verboseconnect(data, conn);
    socks_proxy_cf_free(cf);
  }

  *done = cf->connected;
  return result;
}

static int socks_cf_get_select_socks(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     curl_socket_t *socks)
{
  struct socks_state *sx = cf->ctx;
  int fds;

  fds = cf->next->cft->get_select_socks(cf->next, data, socks);
  if(!fds && cf->next->connected && !cf->connected && sx) {
    /* If we are not connected, the filter below is and has nothing
     * to wait on, we determine what to wait for. */
    socks[0] = Curl_conn_cf_get_socket(cf, data);
    switch(sx->state) {
    case CONNECT_RESOLVING:
    case CONNECT_SOCKS_READ:
    case CONNECT_AUTH_READ:
    case CONNECT_REQ_READ:
    case CONNECT_REQ_READ_MORE:
      fds = GETSOCK_READSOCK(0);
      break;
    default:
      fds = GETSOCK_WRITESOCK(0);
      break;
    }
  }
  return fds;
}

static void socks_proxy_cf_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{

  DEBUGASSERT(cf->next);
  cf->connected = FALSE;
  socks_proxy_cf_free(cf);
  cf->next->cft->close(cf->next, data);
}

static void socks_proxy_cf_destroy(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  (void)data;
  socks_proxy_cf_free(cf);
}

static void socks_cf_get_host(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char **phost,
                              const char **pdisplay_host,
                              int *pport)
{
  (void)data;
  if(!cf->connected) {
    *phost = cf->conn->socks_proxy.host.name;
    *pdisplay_host = cf->conn->http_proxy.host.dispname;
    *pport = (int)cf->conn->socks_proxy.port;
  }
  else {
    cf->next->cft->get_host(cf->next, data, phost, pdisplay_host, pport);
  }
}

struct Curl_cftype Curl_cft_socks_proxy = {
  "SOCKS-PROXYY",
  CF_TYPE_IP_CONNECT,
  0,
  socks_proxy_cf_destroy,
  socks_proxy_cf_connect,
  socks_proxy_cf_close,
  socks_cf_get_host,
  socks_cf_get_select_socks,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
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
