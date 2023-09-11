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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* <netinet/tcp.h> may need it */
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
#ifdef HAVE_LINUX_TCP_H
#include <linux/tcp.h>
#elif defined(HAVE_NETINET_TCP_H)
#include <netinet/tcp.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include "urldata.h"
#include "bufq.h"
#include "sendf.h"
#include "if2ip.h"
#include "strerror.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "select.h"
#include "url.h" /* for Curl_safefree() */
#include "multiif.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "inet_ntop.h"
#include "inet_pton.h"
#include "progress.h"
#include "warnless.h"
#include "conncache.h"
#include "multihandle.h"
#include "rand.h"
#include "share.h"
#include "version_win32.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#if defined(ENABLE_IPV6) && defined(IPV6_V6ONLY) && defined(WIN32)
/* It makes support for IPv4-mapped IPv6 addresses.
 * Linux kernel, NetBSD, FreeBSD and Darwin: default is off;
 * Windows Vista and later: default is on;
 * DragonFly BSD: acts like off, and dummy setting;
 * OpenBSD and earlier Windows: unsupported.
 * Linux: controlled by /proc/sys/net/ipv6/bindv6only.
 */
static void set_ipv6_v6only(curl_socket_t sockfd, int on)
{
  (void)setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on));
}
#else
#define set_ipv6_v6only(x,y)
#endif

static void tcpnodelay(struct Curl_easy *data, curl_socket_t sockfd)
{
#if defined(TCP_NODELAY)
  curl_socklen_t onoff = (curl_socklen_t) 1;
  int level = IPPROTO_TCP;
#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
  char buffer[STRERROR_LEN];
#else
  (void) data;
#endif

  if(setsockopt(sockfd, level, TCP_NODELAY, (void *)&onoff,
                sizeof(onoff)) < 0)
    infof(data, "Could not set TCP_NODELAY: %s",
          Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
#else
  (void)data;
  (void)sockfd;
#endif
}

#ifdef SO_NOSIGPIPE
/* The preferred method on Mac OS X (10.2 and later) to prevent SIGPIPEs when
   sending data to a dead peer (instead of relying on the 4th argument to send
   being MSG_NOSIGNAL). Possibly also existing and in use on other BSD
   systems? */
static void nosigpipe(struct Curl_easy *data,
                      curl_socket_t sockfd)
{
  int onoff = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&onoff,
                sizeof(onoff)) < 0) {
#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
    char buffer[STRERROR_LEN];
    infof(data, "Could not set SO_NOSIGPIPE: %s",
          Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
#endif
  }
}
#else
#define nosigpipe(x,y) Curl_nop_stmt
#endif

#if defined(__DragonFly__) || defined(HAVE_WINSOCK2_H)
/* DragonFlyBSD and Windows use millisecond units */
#define KEEPALIVE_FACTOR(x) (x *= 1000)
#else
#define KEEPALIVE_FACTOR(x)
#endif

#if defined(HAVE_WINSOCK2_H) && !defined(SIO_KEEPALIVE_VALS)
#define SIO_KEEPALIVE_VALS    _WSAIOW(IOC_VENDOR,4)

struct tcp_keepalive {
  u_long onoff;
  u_long keepalivetime;
  u_long keepaliveinterval;
};
#endif

static void
tcpkeepalive(struct Curl_easy *data,
             curl_socket_t sockfd)
{
  int optval = data->set.tcp_keepalive?1:0;

  /* only set IDLE and INTVL if setting KEEPALIVE is successful */
  if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
        (void *)&optval, sizeof(optval)) < 0) {
    infof(data, "Failed to set SO_KEEPALIVE on fd %d", sockfd);
  }
  else {
#if defined(SIO_KEEPALIVE_VALS)
    struct tcp_keepalive vals;
    DWORD dummy;
    vals.onoff = 1;
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    vals.keepalivetime = optval;
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    vals.keepaliveinterval = optval;
    if(WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, (LPVOID) &vals, sizeof(vals),
                NULL, 0, &dummy, NULL, NULL) != 0) {
      infof(data, "Failed to set SIO_KEEPALIVE_VALS on fd %d: %d",
            (int)sockfd, WSAGetLastError());
    }
#else
#ifdef TCP_KEEPIDLE
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPIDLE on fd %d", sockfd);
    }
#elif defined(TCP_KEEPALIVE)
    /* Mac OS X style */
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE,
      (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE on fd %d", sockfd);
    }
#endif
#ifdef TCP_KEEPINTVL
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPINTVL on fd %d", sockfd);
    }
#endif
#endif
  }
}

/**
 * Assign the address `ai` to the Curl_sockaddr_ex `dest` and
 * set the transport used.
 */
void Curl_sock_assign_addr(struct Curl_sockaddr_ex *dest,
                           const struct Curl_addrinfo *ai,
                           int transport)
{
  /*
   * The Curl_sockaddr_ex structure is basically libcurl's external API
   * curl_sockaddr structure with enough space available to directly hold
   * any protocol-specific address structures. The variable declared here
   * will be used to pass / receive data to/from the fopensocket callback
   * if this has been set, before that, it is initialized from parameters.
   */
  dest->family = ai->ai_family;
  switch(transport) {
  case TRNSPRT_TCP:
    dest->socktype = SOCK_STREAM;
    dest->protocol = IPPROTO_TCP;
    break;
  case TRNSPRT_UNIX:
    dest->socktype = SOCK_STREAM;
    dest->protocol = IPPROTO_IP;
    break;
  default: /* UDP and QUIC */
    dest->socktype = SOCK_DGRAM;
    dest->protocol = IPPROTO_UDP;
    break;
  }
  dest->addrlen = ai->ai_addrlen;

  if(dest->addrlen > sizeof(struct Curl_sockaddr_storage))
    dest->addrlen = sizeof(struct Curl_sockaddr_storage);
  memcpy(&dest->sa_addr, ai->ai_addr, dest->addrlen);
}

static CURLcode socket_open(struct Curl_easy *data,
                            struct Curl_sockaddr_ex *addr,
                            curl_socket_t *sockfd)
{
  DEBUGASSERT(data);
  DEBUGASSERT(data->conn);
  if(data->set.fopensocket) {
   /*
    * If the opensocket callback is set, all the destination address
    * information is passed to the callback. Depending on this information the
    * callback may opt to abort the connection, this is indicated returning
    * CURL_SOCKET_BAD; otherwise it will return a not-connected socket. When
    * the callback returns a valid socket the destination address information
    * might have been changed and this 'new' address will actually be used
    * here to connect.
    */
    Curl_set_in_callback(data, true);
    *sockfd = data->set.fopensocket(data->set.opensocket_client,
                                    CURLSOCKTYPE_IPCXN,
                                    (struct curl_sockaddr *)addr);
    Curl_set_in_callback(data, false);
  }
  else {
    /* opensocket callback not set, so simply create the socket now */
    *sockfd = socket(addr->family, addr->socktype, addr->protocol);
  }

  if(*sockfd == CURL_SOCKET_BAD)
    /* no socket, no connection */
    return CURLE_COULDNT_CONNECT;

#if defined(ENABLE_IPV6) && defined(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(data->conn->scope_id && (addr->family == AF_INET6)) {
    struct sockaddr_in6 * const sa6 = (void *)&addr->sa_addr;
    sa6->sin6_scope_id = data->conn->scope_id;
  }
#endif
  return CURLE_OK;
}

/*
 * Create a socket based on info from 'conn' and 'ai'.
 *
 * 'addr' should be a pointer to the correct struct to get data back, or NULL.
 * 'sockfd' must be a pointer to a socket descriptor.
 *
 * If the open socket callback is set, used that!
 *
 */
CURLcode Curl_socket_open(struct Curl_easy *data,
                            const struct Curl_addrinfo *ai,
                            struct Curl_sockaddr_ex *addr,
                            int transport,
                            curl_socket_t *sockfd)
{
  struct Curl_sockaddr_ex dummy;

  if(!addr)
    /* if the caller doesn't want info back, use a local temp copy */
    addr = &dummy;

  Curl_sock_assign_addr(addr, ai, transport);
  return socket_open(data, addr, sockfd);
}

static int socket_close(struct Curl_easy *data, struct connectdata *conn,
                        int use_callback, curl_socket_t sock)
{
  if(use_callback && conn && conn->fclosesocket) {
    int rc;
    Curl_multi_closed(data, sock);
    Curl_set_in_callback(data, true);
    rc = conn->fclosesocket(conn->closesocket_client, sock);
    Curl_set_in_callback(data, false);
    return rc;
  }

  if(conn)
    /* tell the multi-socket code about this */
    Curl_multi_closed(data, sock);

  sclose(sock);

  return 0;
}

/*
 * Close a socket.
 *
 * 'conn' can be NULL, beware!
 */
int Curl_socket_close(struct Curl_easy *data, struct connectdata *conn,
                      curl_socket_t sock)
{
  return socket_close(data, conn, FALSE, sock);
}

#ifdef USE_WINSOCK
/* When you run a program that uses the Windows Sockets API, you may
   experience slow performance when you copy data to a TCP server.

   https://support.microsoft.com/kb/823764

   Work-around: Make the Socket Send Buffer Size Larger Than the Program Send
   Buffer Size

   The problem described in this knowledge-base is applied only to pre-Vista
   Windows.  Following function trying to detect OS version and skips
   SO_SNDBUF adjustment for Windows Vista and above.
*/
#define DETECT_OS_NONE 0
#define DETECT_OS_PREVISTA 1
#define DETECT_OS_VISTA_OR_LATER 2

void Curl_sndbufset(curl_socket_t sockfd)
{
  int val = CURL_MAX_WRITE_SIZE + 32;
  int curval = 0;
  int curlen = sizeof(curval);

  static int detectOsState = DETECT_OS_NONE;

  if(detectOsState == DETECT_OS_NONE) {
    if(curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
                                    VERSION_GREATER_THAN_EQUAL))
      detectOsState = DETECT_OS_VISTA_OR_LATER;
    else
      detectOsState = DETECT_OS_PREVISTA;
  }

  if(detectOsState == DETECT_OS_VISTA_OR_LATER)
    return;

  if(getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&curval, &curlen) == 0)
    if(curval > val)
      return;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&val, sizeof(val));
}
#endif

#ifndef CURL_DISABLE_BINDLOCAL
static CURLcode bindlocal(struct Curl_easy *data, struct connectdata *conn,
                          curl_socket_t sockfd, int af, unsigned int scope)
{
  struct Curl_sockaddr_storage sa;
  struct sockaddr *sock = (struct sockaddr *)&sa;  /* bind to this address */
  curl_socklen_t sizeof_sa = 0; /* size of the data sock points to */
  struct sockaddr_in *si4 = (struct sockaddr_in *)&sa;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&sa;
#endif

  struct Curl_dns_entry *h = NULL;
  unsigned short port = data->set.localport; /* use this port number, 0 for
                                                "random" */
  /* how many port numbers to try to bind to, increasing one at a time */
  int portnum = data->set.localportrange;
  const char *dev = data->set.str[STRING_DEVICE];
  int error;
#ifdef IP_BIND_ADDRESS_NO_PORT
  int on = 1;
#endif
#ifndef ENABLE_IPV6
  (void)scope;
#endif

  /*************************************************************
   * Select device to bind socket to
   *************************************************************/
  if(!dev && !port)
    /* no local kind of binding was requested */
    return CURLE_OK;

  memset(&sa, 0, sizeof(struct Curl_sockaddr_storage));

  if(dev && (strlen(dev)<255) ) {
    char myhost[256] = "";
    int done = 0; /* -1 for error, 1 for address found */
    bool is_interface = FALSE;
    bool is_host = FALSE;
    static const char *if_prefix = "if!";
    static const char *host_prefix = "host!";

    if(strncmp(if_prefix, dev, strlen(if_prefix)) == 0) {
      dev += strlen(if_prefix);
      is_interface = TRUE;
    }
    else if(strncmp(host_prefix, dev, strlen(host_prefix)) == 0) {
      dev += strlen(host_prefix);
      is_host = TRUE;
    }

    /* interface */
    if(!is_host) {
#ifdef SO_BINDTODEVICE
      /*
       * This binds the local socket to a particular interface. This will
       * force even requests to other local interfaces to go out the external
       * interface. Only bind to the interface when specified as interface,
       * not just as a hostname or ip address.
       *
       * The interface might be a VRF, eg: vrf-blue, which means it cannot be
       * converted to an IP address and would fail Curl_if2ip. Simply try to
       * use it straight away.
       */
      if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                    dev, (curl_socklen_t)strlen(dev) + 1) == 0) {
        /* This is often "errno 1, error: Operation not permitted" if you're
         * not running as root or another suitable privileged user. If it
         * succeeds it means the parameter was a valid interface and not an IP
         * address. Return immediately.
         */
        infof(data, "socket successfully bound to interface '%s'", dev);
        return CURLE_OK;
      }
#endif

      switch(Curl_if2ip(af,
#ifdef ENABLE_IPV6
                        scope, conn->scope_id,
#endif
                        dev, myhost, sizeof(myhost))) {
        case IF2IP_NOT_FOUND:
          if(is_interface) {
            /* Do not fall back to treating it as a host name */
            failf(data, "Couldn't bind to interface '%s'", dev);
            return CURLE_INTERFACE_FAILED;
          }
          break;
        case IF2IP_AF_NOT_SUPPORTED:
          /* Signal the caller to try another address family if available */
          return CURLE_UNSUPPORTED_PROTOCOL;
        case IF2IP_FOUND:
          is_interface = TRUE;
          /*
           * We now have the numerical IP address in the 'myhost' buffer
           */
          infof(data, "Local Interface %s is ip %s using address family %i",
                dev, myhost, af);
          done = 1;
          break;
      }
    }
    if(!is_interface) {
      /*
       * This was not an interface, resolve the name as a host name
       * or IP number
       *
       * Temporarily force name resolution to use only the address type
       * of the connection. The resolve functions should really be changed
       * to take a type parameter instead.
       */
      unsigned char ipver = conn->ip_version;
      int rc;

      if(af == AF_INET)
        conn->ip_version = CURL_IPRESOLVE_V4;
#ifdef ENABLE_IPV6
      else if(af == AF_INET6)
        conn->ip_version = CURL_IPRESOLVE_V6;
#endif

      rc = Curl_resolv(data, dev, 80, FALSE, &h);
      if(rc == CURLRESOLV_PENDING)
        (void)Curl_resolver_wait_resolv(data, &h);
      conn->ip_version = ipver;

      if(h) {
        /* convert the resolved address, sizeof myhost >= INET_ADDRSTRLEN */
        Curl_printable_address(h->addr, myhost, sizeof(myhost));
        infof(data, "Name '%s' family %i resolved to '%s' family %i",
              dev, af, myhost, h->addr->ai_family);
        Curl_resolv_unlock(data, h);
        if(af != h->addr->ai_family) {
          /* bad IP version combo, signal the caller to try another address
             family if available */
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        done = 1;
      }
      else {
        /*
         * provided dev was no interface (or interfaces are not supported
         * e.g. solaris) no ip address and no domain we fail here
         */
        done = -1;
      }
    }

    if(done > 0) {
#ifdef ENABLE_IPV6
      /* IPv6 address */
      if(af == AF_INET6) {
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
        char *scope_ptr = strchr(myhost, '%');
        if(scope_ptr)
          *(scope_ptr++) = '\0';
#endif
        if(Curl_inet_pton(AF_INET6, myhost, &si6->sin6_addr) > 0) {
          si6->sin6_family = AF_INET6;
          si6->sin6_port = htons(port);
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
          if(scope_ptr) {
            /* The "myhost" string either comes from Curl_if2ip or from
               Curl_printable_address. The latter returns only numeric scope
               IDs and the former returns none at all.  So the scope ID, if
               present, is known to be numeric */
            unsigned long scope_id = strtoul(scope_ptr, NULL, 10);
            if(scope_id > UINT_MAX)
              return CURLE_UNSUPPORTED_PROTOCOL;

            si6->sin6_scope_id = (unsigned int)scope_id;
          }
#endif
        }
        sizeof_sa = sizeof(struct sockaddr_in6);
      }
      else
#endif
      /* IPv4 address */
      if((af == AF_INET) &&
         (Curl_inet_pton(AF_INET, myhost, &si4->sin_addr) > 0)) {
        si4->sin_family = AF_INET;
        si4->sin_port = htons(port);
        sizeof_sa = sizeof(struct sockaddr_in);
      }
    }

    if(done < 1) {
      /* errorbuf is set false so failf will overwrite any message already in
         the error buffer, so the user receives this error message instead of a
         generic resolve error. */
      data->state.errorbuf = FALSE;
      failf(data, "Couldn't bind to '%s'", dev);
      return CURLE_INTERFACE_FAILED;
    }
  }
  else {
    /* no device was given, prepare sa to match af's needs */
#ifdef ENABLE_IPV6
    if(af == AF_INET6) {
      si6->sin6_family = AF_INET6;
      si6->sin6_port = htons(port);
      sizeof_sa = sizeof(struct sockaddr_in6);
    }
    else
#endif
    if(af == AF_INET) {
      si4->sin_family = AF_INET;
      si4->sin_port = htons(port);
      sizeof_sa = sizeof(struct sockaddr_in);
    }
  }
#ifdef IP_BIND_ADDRESS_NO_PORT
  (void)setsockopt(sockfd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &on, sizeof(on));
#endif
  for(;;) {
    if(bind(sockfd, sock, sizeof_sa) >= 0) {
      /* we succeeded to bind */
      struct Curl_sockaddr_storage add;
      curl_socklen_t size = sizeof(add);
      memset(&add, 0, sizeof(struct Curl_sockaddr_storage));
      if(getsockname(sockfd, (struct sockaddr *) &add, &size) < 0) {
        char buffer[STRERROR_LEN];
        data->state.os_errno = error = SOCKERRNO;
        failf(data, "getsockname() failed with errno %d: %s",
              error, Curl_strerror(error, buffer, sizeof(buffer)));
        return CURLE_INTERFACE_FAILED;
      }
      infof(data, "Local port: %hu", port);
      conn->bits.bound = TRUE;
      return CURLE_OK;
    }

    if(--portnum > 0) {
      port++; /* try next port */
      if(port == 0)
        break;
      infof(data, "Bind to local port %d failed, trying next", port - 1);
      /* We reuse/clobber the port variable here below */
      if(sock->sa_family == AF_INET)
        si4->sin_port = ntohs(port);
#ifdef ENABLE_IPV6
      else
        si6->sin6_port = ntohs(port);
#endif
    }
    else
      break;
  }
  {
    char buffer[STRERROR_LEN];
    data->state.os_errno = error = SOCKERRNO;
    failf(data, "bind failed with errno %d: %s",
          error, Curl_strerror(error, buffer, sizeof(buffer)));
  }

  return CURLE_INTERFACE_FAILED;
}
#endif

/*
 * verifyconnect() returns TRUE if the connect really has happened.
 */
static bool verifyconnect(curl_socket_t sockfd, int *error)
{
  bool rc = TRUE;
#ifdef SO_ERROR
  int err = 0;
  curl_socklen_t errSize = sizeof(err);

#ifdef WIN32
  /*
   * In October 2003 we effectively nullified this function on Windows due to
   * problems with it using all CPU in multi-threaded cases.
   *
   * In May 2004, we bring it back to offer more info back on connect failures.
   * Gisle Vanem could reproduce the former problems with this function, but
   * could avoid them by adding this SleepEx() call below:
   *
   *    "I don't have Rational Quantify, but the hint from his post was
   *    ntdll::NtRemoveIoCompletion(). So I'd assume the SleepEx (or maybe
   *    just Sleep(0) would be enough?) would release whatever
   *    mutex/critical-section the ntdll call is waiting on.
   *
   *    Someone got to verify this on Win-NT 4.0, 2000."
   */

#ifdef _WIN32_WCE
  Sleep(0);
#else
  SleepEx(0, FALSE);
#endif

#endif

  if(0 != getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&err, &errSize))
    err = SOCKERRNO;
#ifdef _WIN32_WCE
  /* Old WinCE versions don't support SO_ERROR */
  if(WSAENOPROTOOPT == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }
#endif
#if defined(EBADIOCTL) && defined(__minix)
  /* Minix 3.1.x doesn't support getsockopt on UDP sockets */
  if(EBADIOCTL == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }
#endif
  if((0 == err) || (EISCONN == err))
    /* we are connected, awesome! */
    rc = TRUE;
  else
    /* This wasn't a successful connect */
    rc = FALSE;
  if(error)
    *error = err;
#else
  (void)sockfd;
  if(error)
    *error = SOCKERRNO;
#endif
  return rc;
}

/**
 * Determine the curl code for a socket connect() == -1 with errno.
 */
static CURLcode socket_connect_result(struct Curl_easy *data,
                                      const char *ipaddress, int error)
{
  switch(error) {
  case EINPROGRESS:
  case EWOULDBLOCK:
#if defined(EAGAIN)
#if (EAGAIN) != (EWOULDBLOCK)
    /* On some platforms EAGAIN and EWOULDBLOCK are the
     * same value, and on others they are different, hence
     * the odd #if
     */
  case EAGAIN:
#endif
#endif
    return CURLE_OK;

  default:
    /* unknown error, fallthrough and try another address! */
#ifdef CURL_DISABLE_VERBOSE_STRINGS
    (void)ipaddress;
#else
    {
      char buffer[STRERROR_LEN];
      infof(data, "Immediate connect fail for %s: %s",
            ipaddress, Curl_strerror(error, buffer, sizeof(buffer)));
    }
#endif
    data->state.os_errno = error;
    /* connect failed */
    return CURLE_COULDNT_CONNECT;
  }
}

/* We have a recv buffer to enhance reads with len < NW_SMALL_READS.
 * This happens often on TLS connections where the TLS implementation
 * tries to read the head of a TLS record, determine the length of the
 * full record and then make a subsequent read for that.
 * On large reads, we will not fill the buffer to avoid the double copy. */
#define NW_RECV_CHUNK_SIZE    (64 * 1024)
#define NW_RECV_CHUNKS         1
#define NW_SMALL_READS        (1024)

struct cf_socket_ctx {
  int transport;
  struct Curl_sockaddr_ex addr;      /* address to connect to */
  curl_socket_t sock;                /* current attempt socket */
  struct bufq recvbuf;               /* used when `buffer_recv` is set */
  char r_ip[MAX_IPADR_LEN];          /* remote IP as string */
  int r_port;                        /* remote port number */
  char l_ip[MAX_IPADR_LEN];          /* local IP as string */
  int l_port;                        /* local port number */
  struct curltime started_at;        /* when socket was created */
  struct curltime connected_at;      /* when socket connected/got first byte */
  struct curltime first_byte_at;     /* when first byte was recvd */
  int error;                         /* errno of last failure or 0 */
#ifdef DEBUGBUILD
  int wblock_percent;                /* percent of writes doing EAGAIN */
  int wpartial_percent;              /* percent of bytes written in send */
#endif
  BIT(got_first_byte);               /* if first byte was received */
  BIT(accepted);                     /* socket was accepted, not connected */
  BIT(active);
  BIT(buffer_recv);
};

static void cf_socket_ctx_init(struct cf_socket_ctx *ctx,
                               const struct Curl_addrinfo *ai,
                               int transport)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->sock = CURL_SOCKET_BAD;
  ctx->transport = transport;
  Curl_sock_assign_addr(&ctx->addr, ai, transport);
  Curl_bufq_init(&ctx->recvbuf, NW_RECV_CHUNK_SIZE, NW_RECV_CHUNKS);
#ifdef DEBUGBUILD
  {
    char *p = getenv("CURL_DBG_SOCK_WBLOCK");
    if(p) {
      long l = strtol(p, NULL, 10);
      if(l >= 0 && l <= 100)
        ctx->wblock_percent = (int)l;
    }
    p = getenv("CURL_DBG_SOCK_WPARTIAL");
    if(p) {
      long l = strtol(p, NULL, 10);
      if(l >= 0 && l <= 100)
        ctx->wpartial_percent = (int)l;
    }
  }
#endif
}

struct reader_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
};

static ssize_t nw_in_read(void *reader_ctx,
                           unsigned char *buf, size_t len,
                           CURLcode *err)
{
  struct reader_ctx *rctx = reader_ctx;
  struct cf_socket_ctx *ctx = rctx->cf->ctx;
  ssize_t nread;

  *err = CURLE_OK;
  nread = sread(ctx->sock, buf, len);

  if(-1 == nread) {
    int sockerr = SOCKERRNO;

    if(
#ifdef WSAEWOULDBLOCK
      /* This is how Windows does it */
      (WSAEWOULDBLOCK == sockerr)
#else
      /* errno may be EWOULDBLOCK or on some systems EAGAIN when it returned
         due to its inability to send off data without blocking. We therefore
         treat both error codes the same here */
      (EWOULDBLOCK == sockerr) || (EAGAIN == sockerr) || (EINTR == sockerr)
#endif
      ) {
      /* this is just a case of EWOULDBLOCK */
      *err = CURLE_AGAIN;
      nread = -1;
    }
    else {
      char buffer[STRERROR_LEN];

      failf(rctx->data, "Recv failure: %s",
            Curl_strerror(sockerr, buffer, sizeof(buffer)));
      rctx->data->state.os_errno = sockerr;
      *err = CURLE_RECV_ERROR;
      nread = -1;
    }
  }
  CURL_TRC_CF(rctx->data, rctx->cf, "nw_in_read(len=%zu) -> %d, err=%d",
              len, (int)nread, *err);
  return nread;
}

static void cf_socket_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  if(ctx && CURL_SOCKET_BAD != ctx->sock) {
    if(ctx->active) {
      /* We share our socket at cf->conn->sock[cf->sockindex] when active.
       * If it is no longer there, someone has stolen (and hopefully
       * closed it) and we just forget about it.
       */
      if(ctx->sock == cf->conn->sock[cf->sockindex]) {
        CURL_TRC_CF(data, cf, "cf_socket_close(%" CURL_FORMAT_SOCKET_T
                    ", active)", ctx->sock);
        socket_close(data, cf->conn, !ctx->accepted, ctx->sock);
        cf->conn->sock[cf->sockindex] = CURL_SOCKET_BAD;
      }
      else {
        CURL_TRC_CF(data, cf, "cf_socket_close(%" CURL_FORMAT_SOCKET_T
                    ") no longer at conn->sock[], discarding", ctx->sock);
        /* TODO: we do not want this to happen. Need to check which
         * code is messing with conn->sock[cf->sockindex] */
      }
      ctx->sock = CURL_SOCKET_BAD;
      if(cf->sockindex == FIRSTSOCKET)
        cf->conn->remote_addr = NULL;
    }
    else {
      /* this is our local socket, we did never publish it */
      CURL_TRC_CF(data, cf, "cf_socket_close(%" CURL_FORMAT_SOCKET_T
                  ", not active)", ctx->sock);
      socket_close(data, cf->conn, !ctx->accepted, ctx->sock);
      ctx->sock = CURL_SOCKET_BAD;
    }
    Curl_bufq_reset(&ctx->recvbuf);
    ctx->active = FALSE;
    ctx->buffer_recv = FALSE;
    memset(&ctx->started_at, 0, sizeof(ctx->started_at));
    memset(&ctx->connected_at, 0, sizeof(ctx->connected_at));
  }

  cf->connected = FALSE;
}

static void cf_socket_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  cf_socket_close(cf, data);
  CURL_TRC_CF(data, cf, "destroy");
  Curl_bufq_free(&ctx->recvbuf);
  free(ctx);
  cf->ctx = NULL;
}

static CURLcode set_local_ip(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

#ifdef HAVE_GETSOCKNAME
  if(!(data->conn->handler->protocol & CURLPROTO_TFTP)) {
    /* TFTP does not connect, so it cannot get the IP like this */

    char buffer[STRERROR_LEN];
    struct Curl_sockaddr_storage ssloc;
    curl_socklen_t slen = sizeof(struct Curl_sockaddr_storage);

    memset(&ssloc, 0, sizeof(ssloc));
    if(getsockname(ctx->sock, (struct sockaddr*) &ssloc, &slen)) {
      int error = SOCKERRNO;
      failf(data, "getsockname() failed with errno %d: %s",
            error, Curl_strerror(error, buffer, sizeof(buffer)));
      return CURLE_FAILED_INIT;
    }
    if(!Curl_addr2string((struct sockaddr*)&ssloc, slen,
                         ctx->l_ip, &ctx->l_port)) {
      failf(data, "ssloc inet_ntop() failed with errno %d: %s",
            errno, Curl_strerror(errno, buffer, sizeof(buffer)));
      return CURLE_FAILED_INIT;
    }
  }
#else
  (void)data;
  ctx->l_ip[0] = 0;
  ctx->l_port = -1;
#endif
  return CURLE_OK;
}

static CURLcode set_remote_ip(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  /* store remote address and port used in this connection attempt */
  if(!Curl_addr2string(&ctx->addr.sa_addr, ctx->addr.addrlen,
                       ctx->r_ip, &ctx->r_port)) {
    char buffer[STRERROR_LEN];

    ctx->error = errno;
    /* malformed address or bug in inet_ntop, try next address */
    failf(data, "sa_addr inet_ntop() failed with errno %d: %s",
          errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode cf_socket_open(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  int error = 0;
  bool isconnected = FALSE;
  CURLcode result = CURLE_COULDNT_CONNECT;
  bool is_tcp;

  (void)data;
  DEBUGASSERT(ctx->sock == CURL_SOCKET_BAD);
  ctx->started_at = Curl_now();
  result = socket_open(data, &ctx->addr, &ctx->sock);
  if(result)
    goto out;

  result = set_remote_ip(cf, data);
  if(result)
    goto out;

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  {
    const char *ipmsg;
#ifdef ENABLE_IPV6
    if(ctx->addr.family == AF_INET6) {
      set_ipv6_v6only(ctx->sock, 0);
      ipmsg = "  Trying [%s]:%d...";
    }
    else
#endif
      ipmsg = "  Trying %s:%d...";
    infof(data, ipmsg, ctx->r_ip, ctx->r_port);
  }
#endif

#ifdef ENABLE_IPV6
  is_tcp = (ctx->addr.family == AF_INET
            || ctx->addr.family == AF_INET6) &&
           ctx->addr.socktype == SOCK_STREAM;
#else
  is_tcp = (ctx->addr.family == AF_INET) &&
           ctx->addr.socktype == SOCK_STREAM;
#endif
  if(is_tcp && data->set.tcp_nodelay)
    tcpnodelay(data, ctx->sock);

  nosigpipe(data, ctx->sock);

  Curl_sndbufset(ctx->sock);

  if(is_tcp && data->set.tcp_keepalive)
    tcpkeepalive(data, ctx->sock);

  if(data->set.fsockopt) {
    /* activate callback for setting socket options */
    Curl_set_in_callback(data, true);
    error = data->set.fsockopt(data->set.sockopt_client,
                               ctx->sock,
                               CURLSOCKTYPE_IPCXN);
    Curl_set_in_callback(data, false);

    if(error == CURL_SOCKOPT_ALREADY_CONNECTED)
      isconnected = TRUE;
    else if(error) {
      result = CURLE_ABORTED_BY_CALLBACK;
      goto out;
    }
  }

#ifndef CURL_DISABLE_BINDLOCAL
  /* possibly bind the local end to an IP, interface or port */
  if(ctx->addr.family == AF_INET
#ifdef ENABLE_IPV6
     || ctx->addr.family == AF_INET6
#endif
    ) {
    result = bindlocal(data, cf->conn, ctx->sock, ctx->addr.family,
                       Curl_ipv6_scope(&ctx->addr.sa_addr));
    if(result) {
      if(result == CURLE_UNSUPPORTED_PROTOCOL) {
        /* The address family is not supported on this interface.
           We can continue trying addresses */
        result = CURLE_COULDNT_CONNECT;
      }
      goto out;
    }
  }
#endif

  /* set socket non-blocking */
  (void)curlx_nonblock(ctx->sock, TRUE);

out:
  if(result) {
    if(ctx->sock != CURL_SOCKET_BAD) {
      socket_close(data, cf->conn, TRUE, ctx->sock);
      ctx->sock = CURL_SOCKET_BAD;
    }
  }
  else if(isconnected) {
    set_local_ip(cf, data);
    ctx->connected_at = Curl_now();
    cf->connected = TRUE;
  }
  CURL_TRC_CF(data, cf, "cf_socket_open() -> %d, fd=%" CURL_FORMAT_SOCKET_T,
              result, ctx->sock);
  return result;
}

static int do_connect(struct Curl_cfilter *cf, struct Curl_easy *data,
                      bool is_tcp_fastopen)
{
  struct cf_socket_ctx *ctx = cf->ctx;
#ifdef TCP_FASTOPEN_CONNECT
  int optval = 1;
#endif
  int rc = -1;

  (void)data;
  if(is_tcp_fastopen) {
#if defined(CONNECT_DATA_IDEMPOTENT) /* Darwin */
#  if defined(HAVE_BUILTIN_AVAILABLE)
    /* while connectx function is available since macOS 10.11 / iOS 9,
       it did not have the interface declared correctly until
       Xcode 9 / macOS SDK 10.13 */
    if(__builtin_available(macOS 10.11, iOS 9.0, tvOS 9.0, watchOS 2.0, *)) {
      sa_endpoints_t endpoints;
      endpoints.sae_srcif = 0;
      endpoints.sae_srcaddr = NULL;
      endpoints.sae_srcaddrlen = 0;
      endpoints.sae_dstaddr = &ctx->addr.sa_addr;
      endpoints.sae_dstaddrlen = ctx->addr.addrlen;

      rc = connectx(ctx->sock, &endpoints, SAE_ASSOCID_ANY,
                    CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                    NULL, 0, NULL, NULL);
    }
    else {
      rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
    }
#  else
    rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
#  endif /* HAVE_BUILTIN_AVAILABLE */
#elif defined(TCP_FASTOPEN_CONNECT) /* Linux >= 4.11 */
    if(setsockopt(ctx->sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                  (void *)&optval, sizeof(optval)) < 0)
      infof(data, "Failed to enable TCP Fast Open on fd %"
            CURL_FORMAT_SOCKET_T, ctx->sock);

    rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
#elif defined(MSG_FASTOPEN) /* old Linux */
    if(cf->conn->given->flags & PROTOPT_SSL)
      rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
    else
      rc = 0; /* Do nothing */
#endif
  }
  else {
    rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
  }
  return rc;
}

static CURLcode cf_tcp_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool blocking, bool *done)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_COULDNT_CONNECT;
  int rc = 0;

  (void)data;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* TODO: need to support blocking connect? */
  if(blocking)
    return CURLE_UNSUPPORTED_PROTOCOL;

  *done = FALSE; /* a very negative world view is best */
  if(ctx->sock == CURL_SOCKET_BAD) {

    result = cf_socket_open(cf, data);
    if(result)
      goto out;

    if(cf->connected) {
      *done = TRUE;
      return CURLE_OK;
    }

    /* Connect TCP socket */
    rc = do_connect(cf, data, cf->conn->bits.tcp_fastopen);
    if(-1 == rc) {
      result = socket_connect_result(data, ctx->r_ip, SOCKERRNO);
      goto out;
    }
  }

#ifdef mpeix
  /* Call this function once now, and ignore the results. We do this to
     "clear" the error state on the socket so that we can later read it
     reliably. This is reported necessary on the MPE/iX operating
     system. */
  (void)verifyconnect(ctx->sock, NULL);
#endif
  /* check socket for connect */
  rc = SOCKET_WRITABLE(ctx->sock, 0);

  if(rc == 0) { /* no connection yet */
    CURL_TRC_CF(data, cf, "not connected yet");
    return CURLE_OK;
  }
  else if(rc == CURL_CSELECT_OUT || cf->conn->bits.tcp_fastopen) {
    if(verifyconnect(ctx->sock, &ctx->error)) {
      /* we are connected with TCP, awesome! */
      ctx->connected_at = Curl_now();
      set_local_ip(cf, data);
      *done = TRUE;
      cf->connected = TRUE;
      CURL_TRC_CF(data, cf, "connected");
      return CURLE_OK;
    }
  }
  else if(rc & CURL_CSELECT_ERR) {
    (void)verifyconnect(ctx->sock, &ctx->error);
    result = CURLE_COULDNT_CONNECT;
  }

out:
  if(result) {
    if(ctx->error) {
      data->state.os_errno = ctx->error;
      SET_SOCKERRNO(ctx->error);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      {
        char buffer[STRERROR_LEN];
        infof(data, "connect to %s port %u failed: %s",
              ctx->r_ip, ctx->r_port,
              Curl_strerror(ctx->error, buffer, sizeof(buffer)));
      }
#endif
    }
    if(ctx->sock != CURL_SOCKET_BAD) {
      socket_close(data, cf->conn, TRUE, ctx->sock);
      ctx->sock = CURL_SOCKET_BAD;
    }
    *done = FALSE;
  }
  return result;
}

static void cf_socket_get_host(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const char **phost,
                               const char **pdisplay_host,
                               int *pport)
{
  (void)data;
  *phost = cf->conn->host.name;
  *pdisplay_host = cf->conn->host.dispname;
  *pport = cf->conn->port;
}

static int cf_socket_get_select_socks(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      curl_socket_t *socks)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  int rc = GETSOCK_BLANK;

  (void)data;
  if(!cf->connected && ctx->sock != CURL_SOCKET_BAD) {
    socks[0] = ctx->sock;
    rc |= GETSOCK_WRITESOCK(0);
  }

  return rc;
}

static bool cf_socket_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  int readable;

  (void)data;
  if(!Curl_bufq_is_empty(&ctx->recvbuf))
    return TRUE;

  readable = SOCKET_READABLE(ctx->sock, 0);
  return (readable > 0 && (readable & CURL_CSELECT_IN));
}

static ssize_t cf_socket_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *buf, size_t len, CURLcode *err)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  curl_socket_t fdsave;
  ssize_t nwritten;
  size_t orig_len = len;

  *err = CURLE_OK;
  fdsave = cf->conn->sock[cf->sockindex];
  cf->conn->sock[cf->sockindex] = ctx->sock;

#ifdef DEBUGBUILD
  /* simulate network blocking/partial writes */
  if(ctx->wblock_percent > 0) {
    unsigned char c;
    Curl_rand(data, &c, 1);
    if(c >= ((100-ctx->wblock_percent)*256/100)) {
      CURL_TRC_CF(data, cf, "send(len=%zu) SIMULATE EWOULDBLOCK", orig_len);
      *err = CURLE_AGAIN;
      nwritten = -1;
      cf->conn->sock[cf->sockindex] = fdsave;
      return nwritten;
    }
  }
  if(cf->cft != &Curl_cft_udp && ctx->wpartial_percent > 0 && len > 8) {
    len = len * ctx->wpartial_percent / 100;
    if(!len)
      len = 1;
    CURL_TRC_CF(data, cf, "send(len=%zu) SIMULATE partial write of %zu bytes",
                orig_len, len);
  }
#endif

#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT) /* Linux */
  if(cf->conn->bits.tcp_fastopen) {
    nwritten = sendto(ctx->sock, buf, len, MSG_FASTOPEN,
                      &cf->conn->remote_addr->sa_addr,
                      cf->conn->remote_addr->addrlen);
    cf->conn->bits.tcp_fastopen = FALSE;
  }
  else
#endif
    nwritten = swrite(ctx->sock, buf, len);

  if(-1 == nwritten) {
    int sockerr = SOCKERRNO;

    if(
#ifdef WSAEWOULDBLOCK
      /* This is how Windows does it */
      (WSAEWOULDBLOCK == sockerr)
#else
      /* errno may be EWOULDBLOCK or on some systems EAGAIN when it returned
         due to its inability to send off data without blocking. We therefore
         treat both error codes the same here */
      (EWOULDBLOCK == sockerr) || (EAGAIN == sockerr) || (EINTR == sockerr) ||
      (EINPROGRESS == sockerr)
#endif
      ) {
      /* this is just a case of EWOULDBLOCK */
      *err = CURLE_AGAIN;
    }
    else {
      char buffer[STRERROR_LEN];
      failf(data, "Send failure: %s",
            Curl_strerror(sockerr, buffer, sizeof(buffer)));
      data->state.os_errno = sockerr;
      *err = CURLE_SEND_ERROR;
    }
  }

  CURL_TRC_CF(data, cf, "send(len=%zu) -> %d, err=%d",
              orig_len, (int)nwritten, *err);
  cf->conn->sock[cf->sockindex] = fdsave;
  return nwritten;
}

static ssize_t cf_socket_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t len, CURLcode *err)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  curl_socket_t fdsave;
  ssize_t nread;

  *err = CURLE_OK;

  fdsave = cf->conn->sock[cf->sockindex];
  cf->conn->sock[cf->sockindex] = ctx->sock;

  if(ctx->buffer_recv && !Curl_bufq_is_empty(&ctx->recvbuf)) {
    CURL_TRC_CF(data, cf, "recv from buffer");
    nread = Curl_bufq_read(&ctx->recvbuf, (unsigned char *)buf, len, err);
  }
  else {
    struct reader_ctx rctx;

    rctx.cf = cf;
    rctx.data = data;

    /* "small" reads may trigger filling our buffer, "large" reads
     * are probably not worth the additional copy */
    if(ctx->buffer_recv && len < NW_SMALL_READS) {
      ssize_t nwritten;
      nwritten = Curl_bufq_slurp(&ctx->recvbuf, nw_in_read, &rctx, err);
      if(nwritten < 0 && !Curl_bufq_is_empty(&ctx->recvbuf)) {
        /* we have a partial read with an error. need to deliver
         * what we got, return the error later. */
        CURL_TRC_CF(data, cf, "partial read: empty buffer first");
        nread = Curl_bufq_read(&ctx->recvbuf, (unsigned char *)buf, len, err);
      }
      else if(nwritten < 0) {
        nread = -1;
        goto out;
      }
      else if(nwritten == 0) {
        /* eof */
        *err = CURLE_OK;
        nread = 0;
      }
      else {
        CURL_TRC_CF(data, cf, "buffered %zd additional bytes", nwritten);
        nread = Curl_bufq_read(&ctx->recvbuf, (unsigned char *)buf, len, err);
      }
    }
    else {
      nread = nw_in_read(&rctx, (unsigned char *)buf, len, err);
    }
  }

out:
  CURL_TRC_CF(data, cf, "recv(len=%zu) -> %d, err=%d", len, (int)nread,
              *err);
  if(nread > 0 && !ctx->got_first_byte) {
    ctx->first_byte_at = Curl_now();
    ctx->got_first_byte = TRUE;
  }
  cf->conn->sock[cf->sockindex] = fdsave;
  return nread;
}

static void conn_set_primary_ip(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
#ifdef HAVE_GETPEERNAME
  struct cf_socket_ctx *ctx = cf->ctx;
  if(!(data->conn->handler->protocol & CURLPROTO_TFTP)) {
    /* TFTP does not connect the endpoint: getpeername() failed with errno
       107: Transport endpoint is not connected */

    char buffer[STRERROR_LEN];
    struct Curl_sockaddr_storage ssrem;
    curl_socklen_t plen;
    int port;

    plen = sizeof(ssrem);
    memset(&ssrem, 0, plen);
    if(getpeername(ctx->sock, (struct sockaddr*) &ssrem, &plen)) {
      int error = SOCKERRNO;
      failf(data, "getpeername() failed with errno %d: %s",
            error, Curl_strerror(error, buffer, sizeof(buffer)));
      return;
    }
    if(!Curl_addr2string((struct sockaddr*)&ssrem, plen,
                         cf->conn->primary_ip, &port)) {
      failf(data, "ssrem inet_ntop() failed with errno %d: %s",
            errno, Curl_strerror(errno, buffer, sizeof(buffer)));
      return;
    }
  }
#else
  cf->conn->primary_ip[0] = 0;
  (void)data;
#endif
}

static void cf_socket_active(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  /* use this socket from now on */
  cf->conn->sock[cf->sockindex] = ctx->sock;
  /* the first socket info gets set at conn and data */
  if(cf->sockindex == FIRSTSOCKET) {
    cf->conn->remote_addr = &ctx->addr;
  #ifdef ENABLE_IPV6
    cf->conn->bits.ipv6 = (ctx->addr.family == AF_INET6)? TRUE : FALSE;
  #endif
    conn_set_primary_ip(cf, data);
    set_local_ip(cf, data);
    Curl_persistconninfo(data, cf->conn, ctx->l_ip, ctx->l_port);
    /* buffering is currently disabled by default because we have stalls
     * in parallel transfers where not all buffered data is consumed and no
     * socket events happen.
     */
    ctx->buffer_recv = FALSE;
  }
  ctx->active = TRUE;
}

static CURLcode cf_socket_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_CONN_INFO_UPDATE:
    cf_socket_active(cf, data);
    break;
  case CF_CTRL_DATA_SETUP:
    Curl_persistconninfo(data, cf->conn, ctx->l_ip, ctx->l_port);
    break;
  }
  return CURLE_OK;
}

static bool cf_socket_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  struct pollfd pfd[1];
  int r;

  *input_pending = FALSE;
  (void)data;
  if(!ctx || ctx->sock == CURL_SOCKET_BAD)
    return FALSE;

  /* Check with 0 timeout if there are any events pending on the socket */
  pfd[0].fd = ctx->sock;
  pfd[0].events = POLLRDNORM|POLLIN|POLLRDBAND|POLLPRI;
  pfd[0].revents = 0;

  r = Curl_poll(pfd, 1, 0);
  if(r < 0) {
    CURL_TRC_CF(data, cf, "is_alive: poll error, assume dead");
    return FALSE;
  }
  else if(r == 0) {
    CURL_TRC_CF(data, cf, "is_alive: poll timeout, assume alive");
    return TRUE;
  }
  else if(pfd[0].revents & (POLLERR|POLLHUP|POLLPRI|POLLNVAL)) {
    CURL_TRC_CF(data, cf, "is_alive: err/hup/etc events, assume dead");
    return FALSE;
  }

  CURL_TRC_CF(data, cf, "is_alive: valid events, looks alive");
  *input_pending = TRUE;
  return TRUE;
}

static CURLcode cf_socket_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_SOCKET:
    DEBUGASSERT(pres2);
    *((curl_socket_t *)pres2) = ctx->sock;
    return CURLE_OK;
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->got_first_byte) {
      timediff_t ms = Curl_timediff(ctx->first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX)? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    switch(ctx->transport) {
    case TRNSPRT_UDP:
    case TRNSPRT_QUIC:
      /* Since UDP connected sockets work different from TCP, we use the
       * time of the first byte from the peer as the "connect" time. */
      if(ctx->got_first_byte) {
        *when = ctx->first_byte_at;
        break;
      }
      /* FALLTHROUGH */
    default:
      *when = ctx->connected_at;
      break;
    }
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_tcp = {
  "TCP",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_tcp_connect,
  cf_socket_close,
  cf_socket_get_host,
  cf_socket_get_select_socks,
  cf_socket_data_pending,
  cf_socket_send,
  cf_socket_recv,
  cf_socket_cntrl,
  cf_socket_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_socket_query,
};

CURLcode Curl_cf_tcp_create(struct Curl_cfilter **pcf,
                            struct Curl_easy *data,
                            struct connectdata *conn,
                            const struct Curl_addrinfo *ai,
                            int transport)
{
  struct cf_socket_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  DEBUGASSERT(transport == TRNSPRT_TCP);
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_socket_ctx_init(ctx, ai, transport);

  result = Curl_cf_create(&cf, &Curl_cft_tcp, ctx);

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

static CURLcode cf_udp_setup_quic(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  int rc;

  /* QUIC needs a connected socket, nonblocking */
  DEBUGASSERT(ctx->sock != CURL_SOCKET_BAD);

  rc = connect(ctx->sock, &ctx->addr.sa_addr, ctx->addr.addrlen);
  if(-1 == rc) {
    return socket_connect_result(data, ctx->r_ip, SOCKERRNO);
  }
  set_local_ip(cf, data);
  CURL_TRC_CF(data, cf, "%s socket %" CURL_FORMAT_SOCKET_T
              " connected: [%s:%d] -> [%s:%d]",
              (ctx->transport == TRNSPRT_QUIC)? "QUIC" : "UDP",
              ctx->sock, ctx->l_ip, ctx->l_port, ctx->r_ip, ctx->r_port);

  (void)curlx_nonblock(ctx->sock, TRUE);
  switch(ctx->addr.family) {
#if defined(__linux__) && defined(IP_MTU_DISCOVER)
  case AF_INET: {
    int val = IP_PMTUDISC_DO;
    (void)setsockopt(ctx->sock, IPPROTO_IP, IP_MTU_DISCOVER, &val,
                     sizeof(val));
    break;
  }
#endif
#if defined(__linux__) && defined(IPV6_MTU_DISCOVER)
  case AF_INET6: {
    int val = IPV6_PMTUDISC_DO;
    (void)setsockopt(ctx->sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val,
                     sizeof(val));
    break;
  }
#endif
  }
  return CURLE_OK;
}

static CURLcode cf_udp_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool blocking, bool *done)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_COULDNT_CONNECT;

  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }
  *done = FALSE;
  if(ctx->sock == CURL_SOCKET_BAD) {
    result = cf_socket_open(cf, data);
    if(result) {
      CURL_TRC_CF(data, cf, "cf_udp_connect(), open failed -> %d", result);
      goto out;
    }

    if(ctx->transport == TRNSPRT_QUIC) {
      result = cf_udp_setup_quic(cf, data);
      if(result)
        goto out;
      CURL_TRC_CF(data, cf, "cf_udp_connect(), opened socket=%"
                  CURL_FORMAT_SOCKET_T " (%s:%d)",
                  ctx->sock, ctx->l_ip, ctx->l_port);
    }
    else {
      CURL_TRC_CF(data, cf, "cf_udp_connect(), opened socket=%"
                  CURL_FORMAT_SOCKET_T " (unconnected)", ctx->sock);
    }
    *done = TRUE;
    cf->connected = TRUE;
  }
out:
  return result;
}

struct Curl_cftype Curl_cft_udp = {
  "UDP",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_udp_connect,
  cf_socket_close,
  cf_socket_get_host,
  cf_socket_get_select_socks,
  cf_socket_data_pending,
  cf_socket_send,
  cf_socket_recv,
  cf_socket_cntrl,
  cf_socket_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_socket_query,
};

CURLcode Curl_cf_udp_create(struct Curl_cfilter **pcf,
                            struct Curl_easy *data,
                            struct connectdata *conn,
                            const struct Curl_addrinfo *ai,
                            int transport)
{
  struct cf_socket_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  DEBUGASSERT(transport == TRNSPRT_UDP || transport == TRNSPRT_QUIC);
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_socket_ctx_init(ctx, ai, transport);

  result = Curl_cf_create(&cf, &Curl_cft_udp, ctx);

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

/* this is the TCP filter which can also handle this case */
struct Curl_cftype Curl_cft_unix = {
  "UNIX",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_tcp_connect,
  cf_socket_close,
  cf_socket_get_host,
  cf_socket_get_select_socks,
  cf_socket_data_pending,
  cf_socket_send,
  cf_socket_recv,
  cf_socket_cntrl,
  cf_socket_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_socket_query,
};

CURLcode Curl_cf_unix_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             const struct Curl_addrinfo *ai,
                             int transport)
{
  struct cf_socket_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  DEBUGASSERT(transport == TRNSPRT_UNIX);
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_socket_ctx_init(ctx, ai, transport);

  result = Curl_cf_create(&cf, &Curl_cft_unix, ctx);

out:
  *pcf = (!result)? cf : NULL;
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

static CURLcode cf_tcp_accept_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool blocking, bool *done)
{
  /* we start accepted, if we ever close, we cannot go on */
  (void)data;
  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}

struct Curl_cftype Curl_cft_tcp_accept = {
  "TCP-ACCEPT",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_tcp_accept_connect,
  cf_socket_close,
  cf_socket_get_host,              /* TODO: not accurate */
  cf_socket_get_select_socks,
  cf_socket_data_pending,
  cf_socket_send,
  cf_socket_recv,
  cf_socket_cntrl,
  cf_socket_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_socket_query,
};

CURLcode Curl_conn_tcp_listen_set(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex, curl_socket_t *s)
{
  CURLcode result;
  struct Curl_cfilter *cf = NULL;
  struct cf_socket_ctx *ctx = NULL;

  /* replace any existing */
  Curl_conn_cf_discard_all(data, conn, sockindex);
  DEBUGASSERT(conn->sock[sockindex] == CURL_SOCKET_BAD);

  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->transport = conn->transport;
  ctx->sock = *s;
  ctx->accepted = FALSE;
  result = Curl_cf_create(&cf, &Curl_cft_tcp_accept, ctx);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);

  conn->sock[sockindex] = ctx->sock;
  set_local_ip(cf, data);
  ctx->active = TRUE;
  ctx->connected_at = Curl_now();
  cf->connected = TRUE;
  CURL_TRC_CF(data, cf, "Curl_conn_tcp_listen_set(%"
              CURL_FORMAT_SOCKET_T ")", ctx->sock);

out:
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }
  return result;
}

static void set_accepted_remote_ip(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
#ifdef HAVE_GETPEERNAME
  char buffer[STRERROR_LEN];
  struct Curl_sockaddr_storage ssrem;
  curl_socklen_t plen;

  ctx->r_ip[0] = 0;
  ctx->r_port = 0;
  plen = sizeof(ssrem);
  memset(&ssrem, 0, plen);
  if(getpeername(ctx->sock, (struct sockaddr*) &ssrem, &plen)) {
    int error = SOCKERRNO;
    failf(data, "getpeername() failed with errno %d: %s",
          error, Curl_strerror(error, buffer, sizeof(buffer)));
    return;
  }
  if(!Curl_addr2string((struct sockaddr*)&ssrem, plen,
                       ctx->r_ip, &ctx->r_port)) {
    failf(data, "ssrem inet_ntop() failed with errno %d: %s",
          errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    return;
  }
#else
  ctx->r_ip[0] = 0;
  ctx->r_port = 0;
  (void)data;
#endif
}

CURLcode Curl_conn_tcp_accepted_set(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex, curl_socket_t *s)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_socket_ctx *ctx = NULL;

  cf = conn->cfilter[sockindex];
  if(!cf || cf->cft != &Curl_cft_tcp_accept)
    return CURLE_FAILED_INIT;

  ctx = cf->ctx;
  /* discard the listen socket */
  socket_close(data, conn, TRUE, ctx->sock);
  ctx->sock = *s;
  conn->sock[sockindex] = ctx->sock;
  set_accepted_remote_ip(cf, data);
  set_local_ip(cf, data);
  ctx->active = TRUE;
  ctx->accepted = TRUE;
  ctx->connected_at = Curl_now();
  cf->connected = TRUE;
  CURL_TRC_CF(data, cf, "accepted_set(sock=%" CURL_FORMAT_SOCKET_T
              ", remote=%s port=%d)",
              ctx->sock, ctx->r_ip, ctx->r_port);

  return CURLE_OK;
}

/**
 * Return TRUE iff `cf` is a socket filter.
 */
static bool cf_is_socket(struct Curl_cfilter *cf)
{
  return cf && (cf->cft == &Curl_cft_tcp ||
                cf->cft == &Curl_cft_udp ||
                cf->cft == &Curl_cft_unix ||
                cf->cft == &Curl_cft_tcp_accept);
}

CURLcode Curl_cf_socket_peek(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             curl_socket_t *psock,
                             const struct Curl_sockaddr_ex **paddr,
                             const char **pr_ip_str, int *pr_port,
                             const char **pl_ip_str, int *pl_port)
{
  if(cf_is_socket(cf) && cf->ctx) {
    struct cf_socket_ctx *ctx = cf->ctx;

    if(psock)
      *psock = ctx->sock;
    if(paddr)
      *paddr = &ctx->addr;
    if(pr_ip_str)
      *pr_ip_str = ctx->r_ip;
    if(pr_port)
      *pr_port = ctx->r_port;
    if(pl_port ||pl_ip_str) {
      set_local_ip(cf, data);
      if(pl_ip_str)
        *pl_ip_str = ctx->l_ip;
      if(pl_port)
        *pl_port = ctx->l_port;
    }
    return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}
