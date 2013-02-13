/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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
#include "strequal.h"
#include "select.h"
#include "connect.h"
#include "timeval.h"
#include "socks.h"

/* The last #include file should be: */
#include "memdebug.h"

/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behaviour which we frown upon, but right now this
 * is what we have...
 */
int Curl_blockread_all(struct connectdata *conn, /* connection data */
                       curl_socket_t sockfd,     /* read from this socket */
                       char *buf,                /* store read data here */
                       ssize_t buffersize,       /* max amount to read */
                       ssize_t *n)               /* amount bytes read */
{
  ssize_t nread;
  ssize_t allread = 0;
  int result;
  long timeleft;
  *n = 0;
  for(;;) {
    timeleft = Curl_timeleft(conn->data, NULL, TRUE);
    if(timeleft < 0) {
      /* we already got the timeout */
      result = CURLE_OPERATION_TIMEDOUT;
      break;
    }
    if(Curl_socket_ready(sockfd, CURL_SOCKET_BAD, timeleft) <= 0) {
      result = ~CURLE_OK;
      break;
    }
    result = Curl_read_plain(sockfd, buf, buffersize, &nread);
    if(CURLE_AGAIN == result)
      continue;
    else if(result)
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

/*
* This function logs in to a SOCKS4 proxy and sends the specifics to the final
* destination server.
*
* Reference :
*   http://socks.permeo.com/protocol/socks4.protocol
*
* Note :
*   Set protocol4a=true for  "SOCKS 4A (Simple Extension to SOCKS 4 Protocol)"
*   Nonsupport "Identification Protocol (RFC1413)"
*/
CURLcode Curl_SOCKS4(const char *proxy_name,
                     const char *hostname,
                     int remote_port,
                     int sockindex,
                     struct connectdata *conn,
                     bool protocol4a)
{
#define SOCKS4REQLEN 262
  unsigned char socksreq[SOCKS4REQLEN]; /* room for SOCKS4 request incl. user
                                           id */
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[sockindex];
  struct SessionHandle *data = conn->data;

  if(Curl_timeleft(data, NULL, TRUE) < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  curlx_nonblock(sock, FALSE);

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
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    int rc;

    rc = Curl_resolv(conn, hostname, remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return CURLE_COULDNT_RESOLVE_PROXY;

    if(rc == CURLRESOLV_PENDING)
      /* ignores the return code, but 'dns' remains NULL on failure */
      (void)Curl_resolver_wait_resolv(conn, &dns);

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if(hp) {
      char buf[64];
      unsigned short ip[4];
      Curl_printable_address(hp, buf, sizeof(buf));

      if(4 == sscanf( buf, "%hu.%hu.%hu.%hu",
                      &ip[0], &ip[1], &ip[2], &ip[3])) {
        /* Set DSTIP */
        socksreq[4] = (unsigned char)ip[0];
        socksreq[5] = (unsigned char)ip[1];
        socksreq[6] = (unsigned char)ip[2];
        socksreq[7] = (unsigned char)ip[3];
      }
      else
        hp = NULL; /* fail! */

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */

    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
            hostname);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  /*
   * This is currently not supporting "Identification Protocol (RFC1413)".
   */
  socksreq[8] = 0; /* ensure empty userid is NUL-terminated */
  if(proxy_name) {
    size_t plen = strlen(proxy_name);
    if(plen >= sizeof(socksreq) - 8) {
      failf(data, "Too long SOCKS proxy name, can't use!\n");
      return CURLE_COULDNT_CONNECT;
    }
    /* copy the proxy name WITH trailing zero */
    memcpy(socksreq + 8, proxy_name, plen+1);
  }

  /*
   * Make connection
   */
  {
    ssize_t actualread;
    ssize_t written;
    ssize_t hostnamelen = 0;
    int packetsize = 9 +
      (int)strlen((char*)socksreq + 8); /* size including NUL */

    /* If SOCKS4a, set special invalid IP address 0.0.0.x */
    if(protocol4a) {
      socksreq[4] = 0;
      socksreq[5] = 0;
      socksreq[6] = 0;
      socksreq[7] = 1;
      /* If still enough room in buffer, also append hostname */
      hostnamelen = (ssize_t)strlen(hostname) + 1; /* length including NUL */
      if(packetsize + hostnamelen <= SOCKS4REQLEN)
        strcpy((char*)socksreq + packetsize, hostname);
      else
        hostnamelen = 0; /* Flag: hostname did not fit in buffer */
    }

    /* Send request */
    code = Curl_write_plain(conn, sock, (char *)socksreq,
                            packetsize + hostnamelen,
                            &written);
    if((code != CURLE_OK) || (written != packetsize + hostnamelen)) {
      failf(data, "Failed to send SOCKS4 connect request.");
      return CURLE_COULDNT_CONNECT;
    }
    if(protocol4a && hostnamelen == 0) {
      /* SOCKS4a with very long hostname - send that name separately */
      hostnamelen = (ssize_t)strlen(hostname) + 1;
      code = Curl_write_plain(conn, sock, (char *)hostname, hostnamelen,
                              &written);
      if((code != CURLE_OK) || (written != hostnamelen)) {
        failf(data, "Failed to send SOCKS4 connect request.");
        return CURLE_COULDNT_CONNECT;
      }
    }

    packetsize = 8; /* receive data size */

    /* Receive response */
    result = Curl_blockread_all(conn, sock, (char *)socksreq, packetsize,
                                &actualread);
    if((result != CURLE_OK) || (actualread != packetsize)) {
      failf(data, "Failed to receive SOCKS4 connect request ack.");
      return CURLE_COULDNT_CONNECT;
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
            "SOCKS4 reply has wrong version, version should be 4.");
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
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    case 92:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", request rejected because SOCKS server cannot connect to "
            "identd on the client.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    case 93:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", request rejected because the client program and identd "
            "report different user-ids.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    default:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", Unknown.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }
  }

  curlx_nonblock(sock, TRUE);

  return CURLE_OK; /* Proxy was successful! */
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
CURLcode Curl_SOCKS5(const char *proxy_name,
                     const char *proxy_password,
                     const char *hostname,
                     int remote_port,
                     int sockindex,
                     struct connectdata *conn)
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

  unsigned char socksreq[600]; /* room for large user/pw (255 max each) */
  ssize_t actualread;
  ssize_t written;
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[sockindex];
  struct SessionHandle *data = conn->data;
  long timeout;
  bool socks5_resolve_local = (conn->proxytype == CURLPROXY_SOCKS5)?TRUE:FALSE;
  const size_t hostname_len = strlen(hostname);
  ssize_t len = 0;

  /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
  if(!socks5_resolve_local && hostname_len > 255) {
    infof(conn->data,"SOCKS5: server resolving disabled for hostnames of "
          "length > 255 [actual len=%zu]\n", hostname_len);
    socks5_resolve_local = TRUE;
  }

  /* get timeout */
  timeout = Curl_timeleft(data, NULL, TRUE);

  if(timeout < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  curlx_nonblock(sock, TRUE);

  /* wait until socket gets connected */
  result = Curl_socket_ready(CURL_SOCKET_BAD, sock, timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5: no connection here");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5: connection timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CURL_CSELECT_ERR) {
    failf(conn->data, "SOCKS5: error occurred during connection");
    return CURLE_COULDNT_CONNECT;
  }

  socksreq[0] = 5; /* version */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  socksreq[1] = (char)(proxy_name ? 3 : 2); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 1; /* gssapi */
  socksreq[4] = 2; /* username/password */
#else
  socksreq[1] = (char)(proxy_name ? 2 : 1); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 2; /* username/password */
#endif

  curlx_nonblock(sock, FALSE);

  code = Curl_write_plain(conn, sock, (char *)socksreq, (2 + (int)socksreq[1]),
                          &written);
  if((code != CURLE_OK) || (written != (2 + (int)socksreq[1]))) {
    failf(data, "Unable to send initial SOCKS5 request.");
    return CURLE_COULDNT_CONNECT;
  }

  curlx_nonblock(sock, TRUE);

  result = Curl_socket_ready(sock, CURL_SOCKET_BAD, timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5 nothing to read");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5 read timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CURL_CSELECT_ERR) {
    failf(conn->data, "SOCKS5 read error occurred");
    return CURLE_RECV_ERROR;
  }

  curlx_nonblock(sock, FALSE);

  result=Curl_blockread_all(conn, sock, (char *)socksreq, 2, &actualread);
  if((result != CURLE_OK) || (actualread != 2)) {
    failf(data, "Unable to receive initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }
  if(socksreq[1] == 0) {
    /* Nothing to do, no authentication needed */
    ;
  }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  else if(socksreq[1] == 1) {
    code = Curl_SOCKS5_gssapi_negotiate(sockindex, conn);
    if(code != CURLE_OK) {
      failf(data, "Unable to negotiate SOCKS5 gssapi context.");
      return CURLE_COULDNT_CONNECT;
    }
  }
#endif
  else if(socksreq[1] == 2) {
    /* Needs user name and password */
    size_t proxy_name_len, proxy_password_len;
    if(proxy_name && proxy_password) {
      proxy_name_len = strlen(proxy_name);
      proxy_password_len = strlen(proxy_password);
    }
    else {
      proxy_name_len = 0;
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
    socksreq[len++] = (unsigned char) proxy_name_len;
    if(proxy_name && proxy_name_len)
      memcpy(socksreq + len, proxy_name, proxy_name_len);
    len += proxy_name_len;
    socksreq[len++] = (unsigned char) proxy_password_len;
    if(proxy_password && proxy_password_len)
      memcpy(socksreq + len, proxy_password, proxy_password_len);
    len += proxy_password_len;

    code = Curl_write_plain(conn, sock, (char *)socksreq, len, &written);
    if((code != CURLE_OK) || (len != written)) {
      failf(data, "Failed to send SOCKS5 sub-negotiation request.");
      return CURLE_COULDNT_CONNECT;
    }

    result=Curl_blockread_all(conn, sock, (char *)socksreq, 2, &actualread);
    if((result != CURLE_OK) || (actualread != 2)) {
      failf(data, "Unable to receive SOCKS5 sub-negotiation response.");
      return CURLE_COULDNT_CONNECT;
    }

    /* ignore the first (VER) byte */
    if(socksreq[1] != 0) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    /* Everything is good so far, user was authenticated! */
  }
  else {
    /* error */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(socksreq[1] == 255) {
#else
    if(socksreq[1] == 1) {
      failf(data,
            "SOCKS5 GSSAPI per-message authentication is not supported.");
      return CURLE_COULDNT_CONNECT;
    }
    else if(socksreq[1] == 255) {
#endif
      if(!proxy_name || !*proxy_name) {
        failf(data,
              "No authentication method was acceptable. (It is quite likely"
              " that the SOCKS5 server wanted a username/password, since none"
              " was supplied to the server on this connection.)");
      }
      else {
        failf(data, "No authentication method was acceptable.");
      }
      return CURLE_COULDNT_CONNECT;
    }
    else {
      failf(data,
            "Undocumented SOCKS5 mode attempted to be used by server.");
      return CURLE_COULDNT_CONNECT;
    }
  }

  /* Authentication is complete, now specify destination to the proxy */
  len = 0;
  socksreq[len++] = 5; /* version (SOCKS5) */
  socksreq[len++] = 1; /* connect */
  socksreq[len++] = 0; /* must be zero */

  if(!socks5_resolve_local) {
    socksreq[len++] = 3; /* ATYP: domain name = 3 */
    socksreq[len++] = (char) hostname_len; /* address length */
    memcpy(&socksreq[len], hostname, hostname_len); /* address str w/o NULL */
    len += hostname_len;
  }
  else {
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp = NULL;
    int rc = Curl_resolv(conn, hostname, remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return CURLE_COULDNT_RESOLVE_HOST;

    if(rc == CURLRESOLV_PENDING) {
      /* this requires that we're in "wait for resolve" state */
      code = Curl_resolver_wait_resolv(conn, &dns);
      if(code != CURLE_OK)
        return code;
    }

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if(hp) {
      struct sockaddr_in *saddr_in;
#ifdef ENABLE_IPV6
      struct sockaddr_in6 *saddr_in6;
#endif
      int i;

      if(hp->ai_family == AF_INET) {
        socksreq[len++] = 1; /* ATYP: IPv4 = 1 */

        saddr_in = (struct sockaddr_in*)hp->ai_addr;
        for(i = 0; i < 4; i++) {
          socksreq[len++] = ((unsigned char*)&saddr_in->sin_addr.s_addr)[i];
          infof(data, "%d\n", socksreq[len-1]);
        }
      }
#ifdef ENABLE_IPV6
      else if(hp->ai_family == AF_INET6) {
        socksreq[len++] = 4; /* ATYP: IPv6 = 4 */

        saddr_in6 = (struct sockaddr_in6*)hp->ai_addr;
        for(i = 0; i < 16; i++) {
          socksreq[len++] = ((unsigned char*)&saddr_in6->sin6_addr.s6_addr)[i];
        }
      }
#endif
      else
        hp = NULL; /* fail! */

      Curl_resolv_unlock(data, dns); /* not used anymore from now on */
    }
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            hostname);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  socksreq[len++] = (unsigned char)((remote_port >> 8) & 0xff); /* PORT MSB */
  socksreq[len++] = (unsigned char)(remote_port & 0xff);        /* PORT LSB */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(conn->socks5_gssapi_enctype) {
    failf(data, "SOCKS5 gssapi protection not yet implemented.");
  }
  else
#endif
    code = Curl_write_plain(conn, sock, (char *)socksreq, len, &written);

  if((code != CURLE_OK) || (len != written)) {
    failf(data, "Failed to send SOCKS5 connect request.");
    return CURLE_COULDNT_CONNECT;
  }

  len = 10; /* minimum packet size is 10 */

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(conn->socks5_gssapi_enctype) {
    failf(data, "SOCKS5 gssapi protection not yet implemented.");
  }
  else
#endif
    result = Curl_blockread_all(conn, sock, (char *)socksreq,
                                len, &actualread);

  if((result != CURLE_OK) || (len != actualread)) {
    failf(data, "Failed to receive SOCKS5 connect request ack.");
    return CURLE_COULDNT_CONNECT;
  }

  if(socksreq[0] != 5) { /* version */
    failf(data,
          "SOCKS5 reply has wrong version, version should be 5.");
    return CURLE_COULDNT_CONNECT;
  }
  if(socksreq[1] != 0) { /* Anything besides 0 is an error */
    if(socksreq[3] == 1) {
      failf(data,
            "Can't complete SOCKS5 connection to %d.%d.%d.%d:%d. (%d)",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    else if(socksreq[3] == 3) {
      failf(data,
            "Can't complete SOCKS5 connection to %s:%d. (%d)",
            hostname,
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    else if(socksreq[3] == 4) {
      failf(data,
            "Can't complete SOCKS5 connection to %02x%02x:%02x%02x:"
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%d. (%d)",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned char)socksreq[8], (unsigned char)socksreq[9],
            (unsigned char)socksreq[10], (unsigned char)socksreq[11],
            (unsigned char)socksreq[12], (unsigned char)socksreq[13],
            (unsigned char)socksreq[14], (unsigned char)socksreq[15],
            (unsigned char)socksreq[16], (unsigned char)socksreq[17],
            (unsigned char)socksreq[18], (unsigned char)socksreq[19],
            ((socksreq[8] << 8) | socksreq[9]),
            socksreq[1]);
    }
    return CURLE_COULDNT_CONNECT;
  }

  /* Fix: in general, returned BND.ADDR is variable length parameter by RFC
     1928, so the reply packet should be read until the end to avoid errors at
     subsequent protocol level.

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
      len -= 10;
      result = Curl_blockread_all(conn, sock, (char *)&socksreq[10],
                                  len, &actualread);
      if((result != CURLE_OK) || (len != actualread)) {
        failf(data, "Failed to receive SOCKS5 connect request ack.");
        return CURLE_COULDNT_CONNECT;
      }
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  }
#endif

  curlx_nonblock(sock, TRUE);
  return CURLE_OK; /* Proxy was successful! */
}

#endif /* CURL_DISABLE_PROXY */

