/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "connect.h"
#include "timeval.h"
#include "socks.h"
#include "multiif.h" /* for getsock macros */

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior. Only used by the SOCKS GSSAPI functions.
 */
int Curl_blockread_all(struct connectdata *conn, /* connection data */
                       curl_socket_t sockfd,     /* read from this socket */
                       char *buf,                /* store read data here */
                       ssize_t buffersize,       /* max amount to read */
                       ssize_t *n)               /* amount bytes read */
{
  ssize_t nread = 0;
  ssize_t allread = 0;
  int result;
  *n = 0;
  for(;;) {
    timediff_t timeleft = Curl_timeleft(conn->data, NULL, TRUE);
    if(timeleft < 0) {
      /* we already got the timeout */
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    if(SOCKET_READABLE(sockfd, timeleft) <= 0) {
      result = ~CURLE_OK;
      break;
    }
    result = Curl_read_plain(sockfd, buf, buffersize, &nread);
    if(CURLE_AGAIN == result)
      continue;
    if(result)
      break;

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

#ifndef DEBUGBUILD
#define sxstate(x,y) socksstate(x,y)
#else
#define sxstate(x,y) socksstate(x,y, __LINE__)
#endif


/* always use this function to change state, to make debugging easier */
static void socksstate(struct connectdata *conn,
                       enum connect_t state
#ifdef DEBUGBUILD
                       , int lineno
#endif
)
{
  enum connect_t oldstate = conn->cnnct.state;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
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

  if(oldstate == state)
    /* don't bother when the new state is the same as the old state */
    return;

  conn->cnnct.state = state;

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  infof(conn->data,
        "SXSTATE: %s => %s conn %p; line %d\n",
        statename[oldstate], statename[conn->cnnct.state], conn,
        lineno);
#endif
}

int Curl_SOCKS_getsock(struct connectdata *conn, curl_socket_t *sock,
                       int sockindex)
{
  int rc = 0;
  sock[0] = conn->sock[sockindex];
  switch(conn->cnnct.state) {
  case CONNECT_RESOLVING:
  case CONNECT_SOCKS_READ:
  case CONNECT_AUTH_READ:
  case CONNECT_REQ_READ:
  case CONNECT_REQ_READ_MORE:
    rc = GETSOCK_READSOCK(0);
    break;
  default:
    rc = GETSOCK_WRITESOCK(0);
    break;
  }
  return rc;
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
CURLcode Curl_SOCKS4(const char *proxy_user,
                     const char *hostname,
                     int remote_port,
                     int sockindex,
                     struct connectdata *conn,
                     bool *done)
{
  const bool protocol4a =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS4A) ? TRUE : FALSE;
  unsigned char *socksreq = &conn->cnnct.socksreq[0];
  CURLcode result;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct Curl_easy *data = conn->data;
  struct connstate *sx = &conn->cnnct;
  struct Curl_dns_entry *dns = NULL;
  ssize_t actualread;
  ssize_t written;

  if(!SOCKS_STATE(sx->state) && !*done)
    sxstate(conn, CONNECT_SOCKS_INIT);

  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    if(conn->bits.httpproxy)
      infof(conn->data, "SOCKS4%s: connecting to HTTP proxy %s port %d\n",
            protocol4a ? "a" : "", hostname, remote_port);

    infof(data, "SOCKS4 communication to %s:%d\n", hostname, remote_port);

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
    socksreq[2] = (unsigned char)((remote_port >> 8) & 0xff); /* PORT MSB */
    socksreq[3] = (unsigned char)(remote_port & 0xff);        /* PORT LSB */

    /* DNS resolve only for SOCKS4, not SOCKS4a */
    if(!protocol4a) {
      enum resolve_t rc =
        Curl_resolv(conn, hostname, remote_port, FALSE, &dns);

      if(rc == CURLRESOLV_ERROR)
        return CURLE_COULDNT_RESOLVE_PROXY;
      else if(rc == CURLRESOLV_PENDING) {
        sxstate(conn, CONNECT_RESOLVING);
        infof(data, "SOCKS4 non-blocking resolve of %s\n", hostname);
        return CURLE_OK;
      }
      sxstate(conn, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }

    /* socks4a doesn't resolve anything locally */
    sxstate(conn, CONNECT_REQ_INIT);
    goto CONNECT_REQ_INIT;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    dns = Curl_fetch_addr(conn, hostname, (int)conn->port);

    if(dns) {
#ifdef CURLRES_ASYNCH
      conn->async.dns = dns;
      conn->async.done = TRUE;
#endif
      infof(data, "Hostname '%s' was found\n", hostname);
      sxstate(conn, CONNECT_RESOLVED);
    }
    else {
      result = Curl_resolv_check(data->conn, &dns);
      /* stay in the state or error out */
      return result;
    }
    /* FALLTHROUGH */
  CONNECT_RESOLVED:
  case CONNECT_RESOLVED: {
    Curl_addrinfo *hp = NULL;
    char buf[64];
    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp = dns->addr;
    if(hp) {
      Curl_printable_address(hp, buf, sizeof(buf));

      if(hp->ai_family == AF_INET) {
        struct sockaddr_in *saddr_in;

        saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
        socksreq[4] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[0];
        socksreq[5] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[1];
        socksreq[6] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[2];
        socksreq[7] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[3];

        infof(data, "SOCKS4 connect to IPv4 %s (locally resolved)\n", buf);
      }
      else {
        hp = NULL; /* fail! */
        failf(data, "SOCKS4 connection to %s not supported\n", buf);
      }

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */
    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
            hostname);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }
    /* FALLTHROUGH */
  CONNECT_REQ_INIT:
  case CONNECT_REQ_INIT:
    /*
     * This is currently not supporting "Identification Protocol (RFC1413)".
     */
    socksreq[8] = 0; /* ensure empty userid is NUL-terminated */
    if(proxy_user) {
      size_t plen = strlen(proxy_user);
      if(plen >= sizeof(sx->socksreq) - 8) {
        failf(data, "Too long SOCKS proxy name, can't use!\n");
        return CURLE_COULDNT_CONNECT;
      }
      /* copy the proxy name WITH trailing zero */
      memcpy(socksreq + 8, proxy_user, plen + 1);
    }

    /*
     * Make connection
     */
    {
      ssize_t packetsize = 9 +
        strlen((char *)socksreq + 8); /* size including NUL */

      /* If SOCKS4a, set special invalid IP address 0.0.0.x */
      if(protocol4a) {
        ssize_t hostnamelen = 0;
        socksreq[4] = 0;
        socksreq[5] = 0;
        socksreq[6] = 0;
        socksreq[7] = 1;
        /* append hostname */
        hostnamelen = (ssize_t)strlen(hostname) + 1; /* length including NUL */
        if(hostnamelen <= 255)
          strcpy((char *)socksreq + packetsize, hostname);
        else {
          failf(data, "SOCKS4: too long host name");
          return CURLE_COULDNT_CONNECT;
        }
        packetsize += hostnamelen;
      }
      sx->outp = socksreq;
      sx->outstanding = packetsize;
      sxstate(conn, CONNECT_REQ_SENDING);
    }
    /* FALLTHROUGH */
  case CONNECT_REQ_SENDING:
    /* Send request */
    result = Curl_write_plain(conn, sockfd, (char *)sx->outp,
                              sx->outstanding, &written);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Failed to send SOCKS4 connect request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(written != sx->outstanding) {
      /* not done, remain in state */
      sx->outstanding -= written;
      sx->outp += written;
      return CURLE_OK;
    }

    /* done sending! */
    sx->outstanding = 8; /* receive data size */
    sx->outp = socksreq;
    sxstate(conn, CONNECT_SOCKS_READ);

    /* FALLTHROUGH */
  case CONNECT_SOCKS_READ:
    /* Receive response */
    result = Curl_read_plain(sockfd, (char *)sx->outp,
                             sx->outstanding, &actualread);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "SOCKS4: Failed receiving connect request ack: %s",
            curl_easy_strerror(result));
      return CURLE_COULDNT_CONNECT;
    }
    else if(actualread != sx->outstanding) {
      /* remain in reading state */
      sx->outstanding -= actualread;
      sx->outp += actualread;
      return CURLE_OK;
    }
    sxstate(conn, CONNECT_DONE);
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
  if(socksreq[0] != 0) {
    failf(data,
          "SOCKS4 reply has wrong version, version should be 0.");
    return CURLE_COULDNT_CONNECT;
  }

  /* Result */
  switch(socksreq[1]) {
  case 90:
    infof(data, "SOCKS4%s request granted.\n", protocol4a?"a":"");
    break;
  case 91:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected or failed.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  case 92:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  case 93:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  default:
    failf(data,
          "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", Unknown.",
          (unsigned char)socksreq[4], (unsigned char)socksreq[5],
          (unsigned char)socksreq[6], (unsigned char)socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLE_COULDNT_CONNECT;
  }

  *done = TRUE;
  return CURLE_OK; /* Proxy was successful! */
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
CURLcode Curl_SOCKS5(const char *proxy_user,
                     const char *proxy_password,
                     const char *hostname,
                     int remote_port,
                     int sockindex,
                     struct connectdata *conn,
                     bool *done)
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
  unsigned char *socksreq = &conn->cnnct.socksreq[0];
  char dest[256] = "unknown";  /* printable hostname:port */
  int idx;
  ssize_t actualread;
  ssize_t written;
  CURLcode result;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct Curl_easy *data = conn->data;
  bool socks5_resolve_local =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS5) ? TRUE : FALSE;
  const size_t hostname_len = strlen(hostname);
  ssize_t len = 0;
  const unsigned long auth = data->set.socks5auth;
  bool allow_gssapi = FALSE;
  struct connstate *sx = &conn->cnnct;
  struct Curl_dns_entry *dns = NULL;

  if(!SOCKS_STATE(sx->state) && !*done)
    sxstate(conn, CONNECT_SOCKS_INIT);

  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    if(conn->bits.httpproxy)
      infof(conn->data, "SOCKS5: connecting to HTTP proxy %s port %d\n",
            hostname, remote_port);

    /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
    if(!socks5_resolve_local && hostname_len > 255) {
      infof(conn->data, "SOCKS5: server resolving disabled for hostnames of "
            "length > 255 [actual len=%zu]\n", hostname_len);
      socks5_resolve_local = TRUE;
    }

    if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
      infof(conn->data,
            "warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: %lu\n",
            auth);
    if(!(auth & CURLAUTH_BASIC))
      /* disable username/password auth */
      proxy_user = NULL;
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
    if(proxy_user)
      socksreq[idx++] = 2; /* username/password */
    /* write the number of authentication methods */
    socksreq[1] = (unsigned char) (idx - 2);

    result = Curl_write_plain(conn, sockfd, (char *)socksreq, idx, &written);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Unable to send initial SOCKS5 request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(written != idx) {
      sxstate(conn, CONNECT_SOCKS_SEND);
      sx->outstanding = idx - written;
      sx->outp = &socksreq[written];
      return CURLE_OK;
    }
    sxstate(conn, CONNECT_SOCKS_READ);
    goto CONNECT_SOCKS_READ_INIT;
  case CONNECT_SOCKS_SEND:
    result = Curl_write_plain(conn, sockfd, (char *)sx->outp,
                              sx->outstanding, &written);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Unable to send initial SOCKS5 request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(written != sx->outstanding) {
      /* not done, remain in state */
      sx->outstanding -= written;
      sx->outp += written;
      return CURLE_OK;
    }
    /* FALLTHROUGH */
  CONNECT_SOCKS_READ_INIT:
  case CONNECT_SOCKS_READ_INIT:
    sx->outstanding = 2; /* expect two bytes */
    sx->outp = socksreq; /* store it here */
    /* FALLTHROUGH */
  case CONNECT_SOCKS_READ:
    result = Curl_read_plain(sockfd, (char *)sx->outp,
                             sx->outstanding, &actualread);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Unable to receive initial SOCKS5 response.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(actualread != sx->outstanding) {
      /* remain in reading state */
      sx->outstanding -= actualread;
      sx->outp += actualread;
      return CURLE_OK;
    }
    else if(socksreq[0] != 5) {
      failf(data, "Received invalid version in initial SOCKS5 response.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(socksreq[1] == 0) {
      /* DONE! No authentication needed. Send request. */
      sxstate(conn, CONNECT_REQ_INIT);
      goto CONNECT_REQ_INIT;
    }
    else if(socksreq[1] == 2) {
      /* regular name + password authentication */
      sxstate(conn, CONNECT_AUTH_INIT);
      goto CONNECT_AUTH_INIT;
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    else if(allow_gssapi && (socksreq[1] == 1)) {
      sxstate(conn, CONNECT_GSSAPI_INIT);
      result = Curl_SOCKS5_gssapi_negotiate(sockindex, conn);
      if(result) {
        failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
        return CURLE_COULDNT_CONNECT;
      }
    }
#endif
    else {
      /* error */
      if(!allow_gssapi && (socksreq[1] == 1)) {
        failf(data,
              "SOCKS5 GSSAPI per-message authentication is not supported.");
        return CURLE_COULDNT_CONNECT;
      }
      else if(socksreq[1] == 255) {
        failf(data, "No authentication method was acceptable.");
        return CURLE_COULDNT_CONNECT;
      }
      failf(data,
            "Undocumented SOCKS5 mode attempted to be used by server.");
      return CURLE_COULDNT_CONNECT;
    }
    break;
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
    if(proxy_user && proxy_password) {
      proxy_user_len = strlen(proxy_user);
      proxy_password_len = strlen(proxy_password);
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
    if(proxy_user && proxy_user_len) {
      /* the length must fit in a single byte */
      if(proxy_user_len >= 255) {
        failf(data, "Excessive user name length for proxy auth");
        return CURLE_BAD_FUNCTION_ARGUMENT;
      }
      memcpy(socksreq + len, proxy_user, proxy_user_len);
    }
    len += proxy_user_len;
    socksreq[len++] = (unsigned char) proxy_password_len;
    if(proxy_password && proxy_password_len) {
      /* the length must fit in a single byte */
      if(proxy_password_len > 255) {
        failf(data, "Excessive password length for proxy auth");
        return CURLE_BAD_FUNCTION_ARGUMENT;
      }
      memcpy(socksreq + len, proxy_password, proxy_password_len);
    }
    len += proxy_password_len;
    sxstate(conn, CONNECT_AUTH_SEND);
    sx->outstanding = len;
    sx->outp = socksreq;
  }
    /* FALLTHROUGH */
  case CONNECT_AUTH_SEND:
    result = Curl_write_plain(conn, sockfd, (char *)sx->outp,
                              sx->outstanding, &written);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Failed to send SOCKS5 sub-negotiation request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(sx->outstanding != written) {
      /* remain in state */
      sx->outstanding -= written;
      sx->outp += written;
      return CURLE_OK;
    }
    sx->outp = socksreq;
    sx->outstanding = 2;
    sxstate(conn, CONNECT_AUTH_READ);
    /* FALLTHROUGH */
  case CONNECT_AUTH_READ:
    result = Curl_read_plain(sockfd, (char *)sx->outp,
                             sx->outstanding, &actualread);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Unable to receive SOCKS5 sub-negotiation response.");
      return CURLE_COULDNT_CONNECT;
    }
    if(actualread != sx->outstanding) {
      /* remain in state */
      sx->outstanding -= actualread;
      sx->outp += actualread;
      return CURLE_OK;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] != 0) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    /* Everything is good so far, user was authenticated! */
    sxstate(conn, CONNECT_REQ_INIT);
    /* FALLTHROUGH */
  CONNECT_REQ_INIT:
  case CONNECT_REQ_INIT:
    if(socks5_resolve_local) {
      enum resolve_t rc = Curl_resolv(conn, hostname, remote_port,
                                      FALSE, &dns);

      if(rc == CURLRESOLV_ERROR)
        return CURLE_COULDNT_RESOLVE_HOST;

      if(rc == CURLRESOLV_PENDING) {
        sxstate(conn, CONNECT_RESOLVING);
        return CURLE_OK;
      }
      sxstate(conn, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }
    goto CONNECT_RESOLVE_REMOTE;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    dns = Curl_fetch_addr(conn, hostname, (int)conn->port);

    if(dns) {
#ifdef CURLRES_ASYNCH
      conn->async.dns = dns;
      conn->async.done = TRUE;
#endif
      infof(data, "SOCKS5: hostname '%s' found\n", hostname);
    }

    if(!dns) {
      result = Curl_resolv_check(data->conn, &dns);
      /* stay in the state or error out */
      return result;
    }
    /* FALLTHROUGH */
  CONNECT_RESOLVED:
  case CONNECT_RESOLVED: {
    Curl_addrinfo *hp = NULL;
    if(dns)
      hp = dns->addr;
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            hostname);
      return CURLE_COULDNT_RESOLVE_HOST;
    }

    if(Curl_printable_address(hp, dest, sizeof(dest))) {
      size_t destlen = strlen(dest);
      msnprintf(dest + destlen, sizeof(dest) - destlen, ":%d", remote_port);
    }
    else {
      strcpy(dest, "unknown");
    }

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

      infof(data, "SOCKS5 connect to IPv4 %s (locally resolved)\n", dest);
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

      infof(data, "SOCKS5 connect to IPv6 %s (locally resolved)\n", dest);
    }
#endif
    else {
      hp = NULL; /* fail! */
      failf(data, "SOCKS5 connection to %s not supported\n", dest);
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
      socksreq[len++] = 3; /* ATYP: domain name = 3 */
      socksreq[len++] = (char) hostname_len; /* one byte address length */
      memcpy(&socksreq[len], hostname, hostname_len); /* address w/o NULL */
      len += hostname_len;
      infof(data, "SOCKS5 connect to %s:%d (remotely resolved)\n",
            hostname, remote_port);
    }
    /* FALLTHROUGH */

  CONNECT_REQ_SEND:
  case CONNECT_REQ_SEND:
    /* PORT MSB */
    socksreq[len++] = (unsigned char)((remote_port >> 8) & 0xff);
    /* PORT LSB */
    socksreq[len++] = (unsigned char)(remote_port & 0xff);

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLE_COULDNT_CONNECT;
    }
#endif
    sx->outp = socksreq;
    sx->outstanding = len;
    sxstate(conn, CONNECT_REQ_SENDING);
    /* FALLTHROUGH */
  case CONNECT_REQ_SENDING:
    result = Curl_write_plain(conn, sockfd, (char *)sx->outp,
                              sx->outstanding, &written);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Failed to send SOCKS5 connect request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(sx->outstanding != written) {
      /* remain in state */
      sx->outstanding -= written;
      sx->outp += written;
      return CURLE_OK;
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLE_COULDNT_CONNECT;
    }
#endif
    sx->outstanding = 10; /* minimum packet size is 10 */
    sx->outp = socksreq;
    sxstate(conn, CONNECT_REQ_READ);
    /* FALLTHROUGH */
  case CONNECT_REQ_READ:
    result = Curl_read_plain(sockfd, (char *)sx->outp,
                             sx->outstanding, &actualread);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Failed to receive SOCKS5 connect request ack.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(actualread != sx->outstanding) {
      /* remain in state */
      sx->outstanding -= actualread;
      sx->outp += actualread;
      return CURLE_OK;
    }

    if(socksreq[0] != 5) { /* version */
      failf(data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(socksreq[1] != 0) { /* Anything besides 0 is an error */
      failf(data, "Can't complete SOCKS5 connection to %s. (%d)",
            hostname, (unsigned char)socksreq[1]);
      return CURLE_COULDNT_CONNECT;
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

    /* At this point we already read first 10 bytes */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(!conn->socks5_gssapi_enctype) {
      /* decrypt_gssapi_blockread already read the whole packet */
#endif
      if(len > 10) {
        sx->outstanding = len - 10; /* get the rest */
        sx->outp = &socksreq[10];
        sxstate(conn, CONNECT_REQ_READ_MORE);
      }
      else {
        sxstate(conn, CONNECT_DONE);
        break;
      }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    }
#endif
    /* FALLTHROUGH */
  case CONNECT_REQ_READ_MORE:
    result = Curl_read_plain(sockfd, (char *)sx->outp,
                             sx->outstanding, &actualread);
    if(result && (CURLE_AGAIN != result)) {
      failf(data, "Failed to receive SOCKS5 connect request ack.");
      return CURLE_COULDNT_CONNECT;
    }
    if(actualread != sx->outstanding) {
      /* remain in state */
      sx->outstanding -= actualread;
      sx->outp += actualread;
      return CURLE_OK;
    }
    sxstate(conn, CONNECT_DONE);
  }
  infof(data, "SOCKS5 request granted.\n");

  *done = TRUE;
  return CURLE_OK; /* Proxy was successful! */
}

#endif /* CURL_DISABLE_PROXY */
