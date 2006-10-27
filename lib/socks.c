/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <string.h>

#ifdef NEED_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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
static int blockread_all(struct connectdata *conn, /* connection data */
                         curl_socket_t sockfd,     /* read from this socket */
                         char *buf,                /* store read data here */
                         ssize_t buffersize,       /* max amount to read */
                         ssize_t *n,               /* amount bytes read */
                         long conn_timeout)        /* timeout for data wait
                                                      relative to
                                                      conn->created */
{
  ssize_t nread;
  ssize_t allread = 0;
  int result;
  struct timeval tvnow;
  long conntime;
  *n = 0;
  do {
    tvnow = Curl_tvnow();
    /* calculating how long connection is establishing */
    conntime = Curl_tvdiff(tvnow, conn->created);
    if(conntime > conn_timeout) {
      /* we already got the timeout */
      result = ~CURLE_OK;
      break;
    }
    if(Curl_select(sockfd, CURL_SOCKET_BAD,
                   (int)(conn_timeout - conntime)) <= 0) {
      result = ~CURLE_OK;
      break;
    }
    result = Curl_read(conn, sockfd, buf, buffersize, &nread);
    if(result)
      break;

    if(buffersize == nread) {
      allread += nread;
      *n = allread;
      result = CURLE_OK;
      break;
    }
    buffersize -= nread;
    buf += nread;
    allread += nread;
  } while(1);
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
*   Nonsupport "SOCKS 4A (Simple Extension to SOCKS 4 Protocol)"
*   Nonsupport "Identification Protocol (RFC1413)"
*/
CURLcode Curl_SOCKS4(const char *proxy_name,
                     struct connectdata *conn)
{
  unsigned char socksreq[262]; /* room for SOCKS4 request incl. user id */
  int result;
  CURLcode code;
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  long timeout;
  struct SessionHandle *data = conn->data;

  /* get timeout */
  if(data->set.timeout && data->set.connecttimeout) {
    if (data->set.timeout < data->set.connecttimeout)
      timeout = data->set.timeout*1000;
    else
      timeout = data->set.connecttimeout*1000;
  }
  else if(data->set.timeout)
    timeout = data->set.timeout*1000;
  else if(data->set.connecttimeout)
    timeout = data->set.connecttimeout*1000;
  else
    timeout = DEFAULT_CONNECT_TIMEOUT;

  Curl_nonblock(sock, FALSE);

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
  *((unsigned short*)&socksreq[2]) = htons(conn->remote_port);

  /* DNS resolve */
  {
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    int rc;

    rc = Curl_resolv(conn, conn->host.name, (int)conn->remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return CURLE_COULDNT_RESOLVE_PROXY;

    if(rc == CURLRESOLV_PENDING)
      /* this requires that we're in "wait for resolve" state */
      rc = Curl_wait_for_resolv(conn, &dns);

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if (hp) {
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
            conn->host.name);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  /*
   * This is currently not supporting "Identification Protocol (RFC1413)".
   */
  socksreq[8] = 0; /* ensure empty userid is NUL-terminated */
  if (proxy_name)
    strlcat((char*)socksreq + 8, proxy_name, sizeof(socksreq) - 8);

  /*
   * Make connection
   */
  {
    ssize_t actualread;
    ssize_t written;
    int packetsize = 9 +
      (int)strlen((char*)socksreq + 8); /* size including NUL */

    /* Send request */
    code = Curl_write(conn, sock, (char *)socksreq, packetsize, &written);
    if ((code != CURLE_OK) || (written != packetsize)) {
      failf(data, "Failed to send SOCKS4 connect request.");
      return CURLE_COULDNT_CONNECT;
    }

    packetsize = 8; /* receive data size */

    /* Receive response */
    result = blockread_all(conn, sock, (char *)socksreq, packetsize,
                           &actualread, timeout);
    if ((result != CURLE_OK) || (actualread != packetsize)) {
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
    if (socksreq[0] != 0) {
      failf(data,
            "SOCKS4 reply has wrong version, version should be 4.");
      return CURLE_COULDNT_CONNECT;
    }

    /* Result */
    switch(socksreq[1])
    {
    case 90:
      infof(data, "SOCKS4 request granted.\n");
      break;
    case 91:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", request rejected or failed.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    case 92:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", request rejected because SOCKS server cannot connect to "
            "identd on the client.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    case 93:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", request rejected because the client program and identd "
            "report different user-ids.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    default:
      failf(data,
            "Can't complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
            ", Unknown.",
            (unsigned char)socksreq[4], (unsigned char)socksreq[5],
            (unsigned char)socksreq[6], (unsigned char)socksreq[7],
            (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
            socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }
  }

  Curl_nonblock(sock, TRUE);

  return CURLE_OK; /* Proxy was successful! */
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
CURLcode Curl_SOCKS5(const char *proxy_name,
                     const char *proxy_password,
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
  curl_socket_t sock = conn->sock[FIRSTSOCKET];
  struct SessionHandle *data = conn->data;
  long timeout;

  /* get timeout */
  if(data->set.timeout && data->set.connecttimeout) {
    if (data->set.timeout < data->set.connecttimeout)
      timeout = data->set.timeout*1000;
    else
      timeout = data->set.connecttimeout*1000;
  }
  else if(data->set.timeout)
    timeout = data->set.timeout*1000;
  else if(data->set.connecttimeout)
    timeout = data->set.connecttimeout*1000;
  else
    timeout = DEFAULT_CONNECT_TIMEOUT;

  Curl_nonblock(sock, TRUE);

  /* wait until socket gets connected */
  result = Curl_select(CURL_SOCKET_BAD, sock, (int)timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5: no connection here");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5: connection timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CSELECT_ERR) {
    failf(conn->data, "SOCKS5: error occured during connection");
    return CURLE_COULDNT_CONNECT;
  }

  socksreq[0] = 5; /* version */
  socksreq[1] = (char)(proxy_name ? 2 : 1); /* number of methods (below) */
  socksreq[2] = 0; /* no authentication */
  socksreq[3] = 2; /* username/password */

  Curl_nonblock(sock, FALSE);

  code = Curl_write(conn, sock, (char *)socksreq, (2 + (int)socksreq[1]),
                      &written);
  if ((code != CURLE_OK) || (written != (2 + (int)socksreq[1]))) {
    failf(data, "Unable to send initial SOCKS5 request.");
    return CURLE_COULDNT_CONNECT;
  }

  Curl_nonblock(sock, TRUE);

  result = Curl_select(sock, CURL_SOCKET_BAD, (int)timeout);

  if(-1 == result) {
    failf(conn->data, "SOCKS5 nothing to read");
    return CURLE_COULDNT_CONNECT;
  }
  else if(0 == result) {
    failf(conn->data, "SOCKS5 read timeout");
    return CURLE_OPERATION_TIMEDOUT;
  }

  if(result & CSELECT_ERR) {
    failf(conn->data, "SOCKS5 read error occured");
    return CURLE_RECV_ERROR;
  }

  Curl_nonblock(sock, FALSE);

  result=blockread_all(conn, sock, (char *)socksreq, 2, &actualread, timeout);
  if ((result != CURLE_OK) || (actualread != 2)) {
    failf(data, "Unable to receive initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }

  if (socksreq[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return CURLE_COULDNT_CONNECT;
  }
  if (socksreq[1] == 0) {
    /* Nothing to do, no authentication needed */
    ;
  }
  else if (socksreq[1] == 2) {
    /* Needs user name and password */
    size_t userlen, pwlen;
    int len;
    if(proxy_name && proxy_password) {
      userlen = strlen(proxy_name);
      pwlen = proxy_password?strlen(proxy_password):0;
    }
    else {
      userlen = 0;
      pwlen = 0;
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
    socksreq[len++] = (char) userlen;
    memcpy(socksreq + len, proxy_name, (int) userlen);
    len += userlen;
    socksreq[len++] = (char) pwlen;
    memcpy(socksreq + len, proxy_password, (int) pwlen);
    len += pwlen;

    code = Curl_write(conn, sock, (char *)socksreq, len, &written);
    if ((code != CURLE_OK) || (len != written)) {
      failf(data, "Failed to send SOCKS5 sub-negotiation request.");
      return CURLE_COULDNT_CONNECT;
    }

    result=blockread_all(conn, sock, (char *)socksreq, 2, &actualread,
                         timeout);
    if ((result != CURLE_OK) || (actualread != 2)) {
      failf(data, "Unable to receive SOCKS5 sub-negotiation response.");
      return CURLE_COULDNT_CONNECT;
    }

    /* ignore the first (VER) byte */
    if (socksreq[1] != 0) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLE_COULDNT_CONNECT;
    }

    /* Everything is good so far, user was authenticated! */
  }
  else {
    /* error */
    if (socksreq[1] == 1) {
      failf(data,
            "SOCKS5 GSSAPI per-message authentication is not supported.");
      return CURLE_COULDNT_CONNECT;
    }
    else if (socksreq[1] == 255) {
      if (!proxy_name || !*proxy_name) {
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
  socksreq[0] = 5; /* version (SOCKS5) */
  socksreq[1] = 1; /* connect */
  socksreq[2] = 0; /* must be zero */
  socksreq[3] = 1; /* IPv4 = 1 */

  {
    struct Curl_dns_entry *dns;
    Curl_addrinfo *hp=NULL;
    int rc = Curl_resolv(conn, conn->host.name, (int)conn->remote_port, &dns);

    if(rc == CURLRESOLV_ERROR)
      return CURLE_COULDNT_RESOLVE_HOST;

    if(rc == CURLRESOLV_PENDING)
      /* this requires that we're in "wait for resolve" state */
      rc = Curl_wait_for_resolv(conn, &dns);

    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns.  It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns)
      hp=dns->addr;
    if (hp) {
      char buf[64];
      unsigned short ip[4];
      Curl_printable_address(hp, buf, sizeof(buf));

      if(4 == sscanf( buf, "%hu.%hu.%hu.%hu",
                      &ip[0], &ip[1], &ip[2], &ip[3])) {
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
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            conn->host.name);
      return CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  *((unsigned short*)&socksreq[8]) = htons(conn->remote_port);

  {
    const int packetsize = 10;

    code = Curl_write(conn, sock, (char *)socksreq, packetsize, &written);
    if ((code != CURLE_OK) || (written != packetsize)) {
      failf(data, "Failed to send SOCKS5 connect request.");
      return CURLE_COULDNT_CONNECT;
    }

    result = blockread_all(conn, sock, (char *)socksreq, packetsize,
                           &actualread, timeout);
    if ((result != CURLE_OK) || (actualread != packetsize)) {
      failf(data, "Failed to receive SOCKS5 connect request ack.");
      return CURLE_COULDNT_CONNECT;
    }

    if (socksreq[0] != 5) { /* version */
      failf(data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return CURLE_COULDNT_CONNECT;
    }
    if (socksreq[1] != 0) { /* Anything besides 0 is an error */
        failf(data,
              "Can't complete SOCKS5 connection to %d.%d.%d.%d:%d. (%d)",
              (unsigned char)socksreq[4], (unsigned char)socksreq[5],
              (unsigned char)socksreq[6], (unsigned char)socksreq[7],
              (unsigned int)ntohs(*(unsigned short*)(&socksreq[8])),
              socksreq[1]);
        return CURLE_COULDNT_CONNECT;
    }
  }

  Curl_nonblock(sock, TRUE);
  return CURLE_OK; /* Proxy was successful! */
}
