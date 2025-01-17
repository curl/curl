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
#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
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

#ifdef __DragonFly__
/* Required for __DragonFly_version */
#include <sys/param.h>
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
#include "strdup.h"
#include "version_win32.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#if defined(USE_IPV6) && defined(IPV6_V6ONLY) && defined(_WIN32)
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
  char buffer[STRERROR_LEN];

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
/* The preferred method on macOS (10.2 and later) to prevent SIGPIPEs when
   sending data to a dead peer (instead of relying on the 4th argument to send
   being MSG_NOSIGNAL). Possibly also existing and in use on other BSD
   systems? */
static void nosigpipe(struct Curl_easy *data,
                      curl_socket_t sockfd)
{
  int onoff = 1;
  (void)data;
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

#if defined(USE_WINSOCK) && \
    defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
/*  Win 10, v 1709 (10.0.16299) and later can use SetSockOpt TCP_KEEP____
 *  so should use seconds */
#define CURL_WINSOCK_KEEP_SSO
#define KEEPALIVE_FACTOR(x)
#elif defined(USE_WINSOCK) || \
   (defined(__sun) && !defined(TCP_KEEPIDLE)) || \
   (defined(__DragonFly__) && __DragonFly_version < 500702) || \
   (defined(_WIN32) && !defined(TCP_KEEPIDLE))
/* Solaris < 11.4, DragonFlyBSD < 500702 and Windows < 10.0.16299
 * use millisecond units. */
#define KEEPALIVE_FACTOR(x) (x *= 1000)
#else
#define KEEPALIVE_FACTOR(x)
#endif

#if defined(USE_WINSOCK) && !defined(SIO_KEEPALIVE_VALS)
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
  int optval = data->set.tcp_keepalive ? 1 : 0;

  /* only set IDLE and INTVL if setting KEEPALIVE is successful */
  if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
        (void *)&optval, sizeof(optval)) < 0) {
    infof(data, "Failed to set SO_KEEPALIVE on fd "
          "%" FMT_SOCKET_T ": errno %d",
          sockfd, SOCKERRNO);
  }
  else {
#if defined(SIO_KEEPALIVE_VALS) /* Windows */
/* Windows 10, version 1709 (10.0.16299) and later versions */
#if defined(CURL_WINSOCK_KEEP_SSO)
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE,
                (const char *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPIDLE on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL,
                (const char *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPINTVL on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
    optval = curlx_sltosi(data->set.tcp_keepcnt);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT,
                (const char *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPCNT on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
#else /* Windows < 10.0.16299 */
    struct tcp_keepalive vals;
    DWORD dummy;
    vals.onoff = 1;
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    vals.keepalivetime = (u_long)optval;
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    vals.keepaliveinterval = (u_long)optval;
    if(WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, (LPVOID) &vals, sizeof(vals),
                NULL, 0, &dummy, NULL, NULL) != 0) {
      infof(data, "Failed to set SIO_KEEPALIVE_VALS on fd "
            "%" FMT_SOCKET_T ": errno %d", sockfd, SOCKERRNO);
    }
#endif
#else /* !Windows */
#ifdef TCP_KEEPIDLE
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPIDLE on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
#elif defined(TCP_KEEPALIVE)
    /* macOS style */
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE,
      (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
#elif defined(TCP_KEEPALIVE_THRESHOLD)
    /* Solaris <11.4 style */
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE_THRESHOLD,
      (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE_THRESHOLD on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
#endif
#ifdef TCP_KEEPINTVL
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPINTVL on fd "
            "%" FMT_SOCKET_T ": errno %d",
            sockfd, SOCKERRNO);
    }
#elif defined(TCP_KEEPALIVE_ABORT_THRESHOLD)
    /* Solaris <11.4 style */
    /* TCP_KEEPALIVE_ABORT_THRESHOLD should equal to
     * TCP_KEEPCNT * TCP_KEEPINTVL on other platforms.
     * The default value of TCP_KEEPCNT is 9 on Linux,
     * 8 on *BSD/macOS, 5 or 10 on Windows. We use the
     * default config for Solaris <11.4 because there is
     * no default value for TCP_KEEPCNT on Solaris 11.4.
     *
     * Note that the consequent probes will not be sent
     * at equal intervals on Solaris, but will be sent
     * using the exponential backoff algorithm. */
    optval = curlx_sltosi(data->set.tcp_keepcnt) *
             curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE_ABORT_THRESHOLD,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE_ABORT_THRESHOLD on fd "
            "%" FMT_SOCKET_T ": errno %d", sockfd, SOCKERRNO);
    }
#endif
#ifdef TCP_KEEPCNT
    optval = curlx_sltosi(data->set.tcp_keepcnt);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT,
                (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPCNT on fd "
            "%" FMT_SOCKET_T ": errno %d", sockfd, SOCKERRNO);
    }
#endif
#endif
  }
}

/**
 * Assign the address `ai` to the Curl_sockaddr_ex `dest` and
 * set the transport used.
 */
CURLcode Curl_sock_assign_addr(struct Curl_sockaddr_ex *dest,
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
  dest->addrlen = (unsigned int)ai->ai_addrlen;

  if(dest->addrlen > sizeof(struct Curl_sockaddr_storage)) {
    DEBUGASSERT(0);
    return CURLE_TOO_LARGE;
  }

  memcpy(&dest->curl_sa_addr, ai->ai_addr, dest->addrlen);
  return CURLE_OK;
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
    Curl_set_in_callback(data, TRUE);
    *sockfd = data->set.fopensocket(data->set.opensocket_client,
                                    CURLSOCKTYPE_IPCXN,
                                    (struct curl_sockaddr *)addr);
    Curl_set_in_callback(data, FALSE);
  }
  else {
    /* opensocket callback not set, so simply create the socket now */
    *sockfd = socket(addr->family, addr->socktype, addr->protocol);
  }

  if(*sockfd == CURL_SOCKET_BAD)
    /* no socket, no connection */
    return CURLE_COULDNT_CONNECT;

#if defined(USE_IPV6) && defined(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(data->conn->scope_id && (addr->family == AF_INET6)) {
    struct sockaddr_in6 * const sa6 = (void *)&addr->curl_sa_addr;
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
  CURLcode result;

  if(!addr)
    /* if the caller does not want info back, use a local temp copy */
    addr = &dummy;

  result = Curl_sock_assign_addr(addr, ai, transport);
  if(result)
    return result;

  return socket_open(data, addr, sockfd);
}

static int socket_close(struct Curl_easy *data, struct connectdata *conn,
                        int use_callback, curl_socket_t sock)
{
  if(CURL_SOCKET_BAD == sock)
    return 0;

  if(use_callback && conn && conn->fclosesocket) {
    int rc;
    Curl_multi_closed(data, sock);
    Curl_set_in_callback(data, TRUE);
    rc = conn->fclosesocket(conn->closesocket_client, sock);
    Curl_set_in_callback(data, FALSE);
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
   Windows. Following function trying to detect OS version and skips
   SO_SNDBUF adjustment for Windows Vista and above.
*/
#define DETECT_OS_NONE 0
#define DETECT_OS_PREVISTA 1
#define DETECT_OS_VISTA_OR_LATER 2

void Curl_sndbuf_init(curl_socket_t sockfd)
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
#endif /* USE_WINSOCK */

/*
 * Curl_parse_interface()
 *
 * This is used to parse interface argument in the following formats.
 * In all the examples, `host` can be an IP address or a hostname.
 *
 *   <iface_or_host> - can be either an interface name or a host.
 *   if!<iface> - interface name.
 *   host!<host> - hostname.
 *   ifhost!<iface>!<host> - interface name and hostname.
 *
 * Parameters:
 *
 * input  [in]     - input string.
 * len    [in]     - length of the input string.
 * dev    [in/out] - address where a pointer to newly allocated memory
 *                   holding the interface-or-host will be stored upon
 *                   completion.
 * iface  [in/out] - address where a pointer to newly allocated memory
 *                   holding the interface will be stored upon completion.
 * host   [in/out] - address where a pointer to newly allocated memory
 *                   holding the host will be stored upon completion.
 *
 * Returns CURLE_OK on success.
 */
CURLcode Curl_parse_interface(const char *input,
                              char **dev, char **iface, char **host)
{
  static const char if_prefix[] = "if!";
  static const char host_prefix[] = "host!";
  static const char if_host_prefix[] = "ifhost!";
  size_t len;

  DEBUGASSERT(dev);
  DEBUGASSERT(iface);
  DEBUGASSERT(host);

  len = strlen(input);
  if(len > 512)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(!strncmp(if_prefix, input, strlen(if_prefix))) {
    input += strlen(if_prefix);
    if(!*input)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    *iface = Curl_memdup0(input, len - strlen(if_prefix));
    return *iface ? CURLE_OK : CURLE_OUT_OF_MEMORY;
  }
  else if(!strncmp(host_prefix, input, strlen(host_prefix))) {
    input += strlen(host_prefix);
    if(!*input)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    *host = Curl_memdup0(input, len - strlen(host_prefix));
    return *host ? CURLE_OK : CURLE_OUT_OF_MEMORY;
  }
  else if(!strncmp(if_host_prefix, input, strlen(if_host_prefix))) {
    const char *host_part;
    input += strlen(if_host_prefix);
    len -= strlen(if_host_prefix);
    host_part = memchr(input, '!', len);
    if(!host_part || !*(host_part + 1))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    *iface = Curl_memdup0(input, host_part - input);
    if(!*iface)
      return CURLE_OUT_OF_MEMORY;
    ++host_part;
    *host = Curl_memdup0(host_part, len - (host_part - input));
    if(!*host) {
      free(*iface);
      *iface = NULL;
      return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
  }

  if(!*input)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  *dev = Curl_memdup0(input, len);
  return *dev ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

#ifndef CURL_DISABLE_BINDLOCAL
static CURLcode bindlocal(struct Curl_easy *data, struct connectdata *conn,
                          curl_socket_t sockfd, int af, unsigned int scope)
{
  struct Curl_sockaddr_storage sa;
  struct sockaddr *sock = (struct sockaddr *)&sa;  /* bind to this address */
  curl_socklen_t sizeof_sa = 0; /* size of the data sock points to */
  struct sockaddr_in *si4 = (struct sockaddr_in *)&sa;
#ifdef USE_IPV6
  struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&sa;
#endif

  struct Curl_dns_entry *h = NULL;
  unsigned short port = data->set.localport; /* use this port number, 0 for
                                                "random" */
  /* how many port numbers to try to bind to, increasing one at a time */
  int portnum = data->set.localportrange;
  const char *dev = data->set.str[STRING_DEVICE];
  const char *iface_input = data->set.str[STRING_INTERFACE];
  const char *host_input = data->set.str[STRING_BINDHOST];
  const char *iface = iface_input ? iface_input : dev;
  const char *host = host_input ? host_input : dev;
  int error;
#ifdef IP_BIND_ADDRESS_NO_PORT
  int on = 1;
#endif
#ifndef USE_IPV6
  (void)scope;
#endif

  /*************************************************************
   * Select device to bind socket to
   *************************************************************/
  if(!iface && !host && !port)
    /* no local kind of binding was requested */
    return CURLE_OK;
  else if(iface && (strlen(iface) >= 255) )
    return CURLE_BAD_FUNCTION_ARGUMENT;

  memset(&sa, 0, sizeof(struct Curl_sockaddr_storage));

  if(iface || host) {
    char myhost[256] = "";
    int done = 0; /* -1 for error, 1 for address found */
    if2ip_result_t if2ip_result = IF2IP_NOT_FOUND;

#ifdef SO_BINDTODEVICE
    if(iface) {
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
                    iface, (curl_socklen_t)strlen(iface) + 1) == 0) {
        /* This is often "errno 1, error: Operation not permitted" if you are
         * not running as root or another suitable privileged user. If it
         * succeeds it means the parameter was a valid interface and not an IP
         * address. Return immediately.
         */
        if(!host_input) {
          infof(data, "socket successfully bound to interface '%s'", iface);
          return CURLE_OK;
        }
      }
    }
#endif
    if(!host_input) {
      /* Discover IP from input device, then bind to it */
      if2ip_result = Curl_if2ip(af,
#ifdef USE_IPV6
                      scope, conn->scope_id,
#endif
                      iface, myhost, sizeof(myhost));
    }
    switch(if2ip_result) {
      case IF2IP_NOT_FOUND:
        if(iface_input && !host_input) {
          /* Do not fall back to treating it as a hostname */
          char buffer[STRERROR_LEN];
          data->state.os_errno = error = SOCKERRNO;
          failf(data, "Couldn't bind to interface '%s' with errno %d: %s",
                iface, error, Curl_strerror(error, buffer, sizeof(buffer)));
          return CURLE_INTERFACE_FAILED;
        }
        break;
      case IF2IP_AF_NOT_SUPPORTED:
        /* Signal the caller to try another address family if available */
        return CURLE_UNSUPPORTED_PROTOCOL;
      case IF2IP_FOUND:
        /*
          * We now have the numerical IP address in the 'myhost' buffer
          */
        host = myhost;
        infof(data, "Local Interface %s is ip %s using address family %i",
              iface, host, af);
        done = 1;
        break;
    }
    if(!iface_input || host_input) {
      /*
       * This was not an interface, resolve the name as a hostname
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
#ifdef USE_IPV6
      else if(af == AF_INET6)
        conn->ip_version = CURL_IPRESOLVE_V6;
#endif

      rc = Curl_resolv(data, host, 80, FALSE, &h);
      if(rc == CURLRESOLV_PENDING)
        (void)Curl_resolver_wait_resolv(data, &h);
      conn->ip_version = ipver;

      if(h) {
        int h_af = h->addr->ai_family;
        /* convert the resolved address, sizeof myhost >= INET_ADDRSTRLEN */
        Curl_printable_address(h->addr, myhost, sizeof(myhost));
        infof(data, "Name '%s' family %i resolved to '%s' family %i",
              host, af, myhost, h_af);
        Curl_resolv_unlink(data, &h); /* this will NULL, potential free h */
        if(af != h_af) {
          /* bad IP version combo, signal the caller to try another address
             family if available */
          return CURLE_UNSUPPORTED_PROTOCOL;
        }
        done = 1;
      }
      else {
        /*
         * provided dev was no interface (or interfaces are not supported
         * e.g. Solaris) no ip address and no domain we fail here
         */
        done = -1;
      }
    }

    if(done > 0) {
#ifdef USE_IPV6
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
               IDs and the former returns none at all. So the scope ID, if
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
      char buffer[STRERROR_LEN];
      data->state.errorbuf = FALSE;
      data->state.os_errno = error = SOCKERRNO;
      failf(data, "Couldn't bind to '%s' with errno %d: %s",
            host, error, Curl_strerror(error, buffer, sizeof(buffer)));
      return CURLE_INTERFACE_FAILED;
    }
  }
  else {
    /* no device was given, prepare sa to match af's needs */
#ifdef USE_IPV6
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
#ifdef USE_IPV6
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

#ifdef _WIN32
  /*
   * In October 2003 we effectively nullified this function on Windows due to
   * problems with it using all CPU in multi-threaded cases.
   *
   * In May 2004, we bring it back to offer more info back on connect failures.
   * Gisle Vanem could reproduce the former problems with this function, but
   * could avoid them by adding this SleepEx() call below:
   *
   *    "I do not have Rational Quantify, but the hint from his post was
   *    ntdll::NtRemoveIoCompletion(). I would assume the SleepEx (or maybe
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
  /* Old Windows CE versions do not support SO_ERROR */
  if(WSAENOPROTOOPT == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }
#endif
#if defined(EBADIOCTL) && defined(__minix)
  /* Minix 3.1.x does not support getsockopt on UDP sockets */
  if(EBADIOCTL == err) {
    SET_SOCKERRNO(0);
    err = 0;
  }
#endif
  if((0 == err) || (EISCONN == err))
    /* we are connected, awesome! */
    rc = TRUE;
  else
    /* This was not a successful connect */
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
  struct ip_quadruple ip;            /* The IP quadruple 2x(addr+port) */
  struct curltime started_at;        /* when socket was created */
  struct curltime connected_at;      /* when socket connected/got first byte */
  struct curltime first_byte_at;     /* when first byte was recvd */
#ifdef USE_WINSOCK
  struct curltime last_sndbuf_query_at;  /* when SO_SNDBUF last queried */
  ULONG sndbuf_size;                     /* the last set SO_SNDBUF size */
#endif
  int error;                         /* errno of last failure or 0 */
#ifdef DEBUGBUILD
  int wblock_percent;                /* percent of writes doing EAGAIN */
  int wpartial_percent;              /* percent of bytes written in send */
  int rblock_percent;                /* percent of reads doing EAGAIN */
  size_t recv_max;                  /* max enforced read size */
#endif
  BIT(got_first_byte);               /* if first byte was received */
  BIT(listening);                    /* socket is listening */
  BIT(accepted);                     /* socket was accepted, not connected */
  BIT(sock_connected);               /* socket is "connected", e.g. in UDP */
  BIT(active);
};

static CURLcode cf_socket_ctx_init(struct cf_socket_ctx *ctx,
                                   const struct Curl_addrinfo *ai,
                                   int transport)
{
  CURLcode result;

  memset(ctx, 0, sizeof(*ctx));
  ctx->sock = CURL_SOCKET_BAD;
  ctx->transport = transport;

  result = Curl_sock_assign_addr(&ctx->addr, ai, transport);
  if(result)
    return result;

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
    p = getenv("CURL_DBG_SOCK_RBLOCK");
    if(p) {
      long l = strtol(p, NULL, 10);
      if(l >= 0 && l <= 100)
        ctx->rblock_percent = (int)l;
    }
    p = getenv("CURL_DBG_SOCK_RMAX");
    if(p) {
      long l = strtol(p, NULL, 10);
      if(l >= 0)
        ctx->recv_max = (size_t)l;
    }
  }
#endif

  return result;
}

static void cf_socket_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  if(ctx && CURL_SOCKET_BAD != ctx->sock) {
    CURL_TRC_CF(data, cf, "cf_socket_close(%" FMT_SOCKET_T ")", ctx->sock);
    if(ctx->sock == cf->conn->sock[cf->sockindex])
      cf->conn->sock[cf->sockindex] = CURL_SOCKET_BAD;
    socket_close(data, cf->conn, !ctx->accepted, ctx->sock);
    ctx->sock = CURL_SOCKET_BAD;
    if(ctx->active && cf->sockindex == FIRSTSOCKET)
      cf->conn->remote_addr = NULL;
    ctx->active = FALSE;
    memset(&ctx->started_at, 0, sizeof(ctx->started_at));
    memset(&ctx->connected_at, 0, sizeof(ctx->connected_at));
  }

  cf->connected = FALSE;
}

static CURLcode cf_socket_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *done)
{
  if(cf->connected) {
    struct cf_socket_ctx *ctx = cf->ctx;

    CURL_TRC_CF(data, cf, "cf_socket_shutdown(%" FMT_SOCKET_T ")", ctx->sock);
    /* On TCP, and when the socket looks well and non-blocking mode
     * can be enabled, receive dangling bytes before close to avoid
     * entering RST states unnecessarily. */
    if(ctx->sock != CURL_SOCKET_BAD &&
       ctx->transport == TRNSPRT_TCP &&
       (curlx_nonblock(ctx->sock, TRUE) >= 0)) {
      unsigned char buf[1024];
      (void)sread(ctx->sock, buf, sizeof(buf));
    }
  }
  *done = TRUE;
  return CURLE_OK;
}

static void cf_socket_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  cf_socket_close(cf, data);
  CURL_TRC_CF(data, cf, "destroy");
  free(ctx);
  cf->ctx = NULL;
}

static CURLcode set_local_ip(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

#ifdef HAVE_GETSOCKNAME
  if((ctx->sock != CURL_SOCKET_BAD) &&
     !(data->conn->handler->protocol & CURLPROTO_TFTP)) {
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
                         ctx->ip.local_ip, &ctx->ip.local_port)) {
      failf(data, "ssloc inet_ntop() failed with errno %d: %s",
            errno, Curl_strerror(errno, buffer, sizeof(buffer)));
      return CURLE_FAILED_INIT;
    }
  }
#else
  (void)data;
  ctx->ip.local_ip[0] = 0;
  ctx->ip.local_port = -1;
#endif
  return CURLE_OK;
}

static CURLcode set_remote_ip(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  /* store remote address and port used in this connection attempt */
  if(!Curl_addr2string(&ctx->addr.curl_sa_addr,
                       (curl_socklen_t)ctx->addr.addrlen,
                       ctx->ip.remote_ip, &ctx->ip.remote_port)) {
    char buffer[STRERROR_LEN];

    ctx->error = errno;
    /* malformed address or bug in inet_ntop, try next address */
    failf(data, "curl_sa_addr inet_ntop() failed with errno %d: %s",
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
#ifdef SOCK_NONBLOCK
  /* Do not tuck SOCK_NONBLOCK into socktype when opensocket callback is set
   * because we would not know how socketype is about to be used in the
   * callback, SOCK_NONBLOCK might get factored out before calling socket().
   */
  if(!data->set.fopensocket)
    ctx->addr.socktype |= SOCK_NONBLOCK;
#endif
  result = socket_open(data, &ctx->addr, &ctx->sock);
#ifdef SOCK_NONBLOCK
  /* Restore the socktype after the socket is created. */
  if(!data->set.fopensocket)
    ctx->addr.socktype &= ~SOCK_NONBLOCK;
#endif
  if(result)
    goto out;

  result = set_remote_ip(cf, data);
  if(result)
    goto out;

#ifdef USE_IPV6
  if(ctx->addr.family == AF_INET6) {
    set_ipv6_v6only(ctx->sock, 0);
    infof(data, "  Trying [%s]:%d...", ctx->ip.remote_ip, ctx->ip.remote_port);
  }
  else
#endif
    infof(data, "  Trying %s:%d...", ctx->ip.remote_ip, ctx->ip.remote_port);

#ifdef USE_IPV6
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

  Curl_sndbuf_init(ctx->sock);

  if(is_tcp && data->set.tcp_keepalive)
    tcpkeepalive(data, ctx->sock);

  if(data->set.fsockopt) {
    /* activate callback for setting socket options */
    Curl_set_in_callback(data, TRUE);
    error = data->set.fsockopt(data->set.sockopt_client,
                               ctx->sock,
                               CURLSOCKTYPE_IPCXN);
    Curl_set_in_callback(data, FALSE);

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
#ifdef USE_IPV6
     || ctx->addr.family == AF_INET6
#endif
    ) {
    result = bindlocal(data, cf->conn, ctx->sock, ctx->addr.family,
                       Curl_ipv6_scope(&ctx->addr.curl_sa_addr));
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

#ifndef SOCK_NONBLOCK
  /* Set socket non-blocking, must be a non-blocking socket for
   * a non-blocking connect. */
  error = curlx_nonblock(ctx->sock, TRUE);
  if(error < 0) {
    result = CURLE_UNSUPPORTED_PROTOCOL;
    ctx->error = SOCKERRNO;
    goto out;
  }
#else
  if(data->set.fopensocket) {
    /* Set socket non-blocking, must be a non-blocking socket for
     * a non-blocking connect. */
    error = curlx_nonblock(ctx->sock, TRUE);
    if(error < 0) {
      result = CURLE_UNSUPPORTED_PROTOCOL;
      ctx->error = SOCKERRNO;
      goto out;
    }
  }
#endif
  ctx->sock_connected = (ctx->addr.socktype != SOCK_DGRAM);
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
  CURL_TRC_CF(data, cf, "cf_socket_open() -> %d, fd=%" FMT_SOCKET_T,
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
      endpoints.sae_dstaddr = &ctx->addr.curl_sa_addr;
      endpoints.sae_dstaddrlen = ctx->addr.addrlen;

      rc = connectx(ctx->sock, &endpoints, SAE_ASSOCID_ANY,
                    CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT,
                    NULL, 0, NULL, NULL);
    }
    else {
      rc = connect(ctx->sock, &ctx->addr.curl_sa_addr, ctx->addr.addrlen);
    }
#  else
    rc = connect(ctx->sock, &ctx->addr.curl_sa_addr, ctx->addr.addrlen);
#  endif /* HAVE_BUILTIN_AVAILABLE */
#elif defined(TCP_FASTOPEN_CONNECT) /* Linux >= 4.11 */
    if(setsockopt(ctx->sock, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                  (void *)&optval, sizeof(optval)) < 0)
      infof(data, "Failed to enable TCP Fast Open on fd %" FMT_SOCKET_T,
            ctx->sock);

    rc = connect(ctx->sock, &ctx->addr.curl_sa_addr, ctx->addr.addrlen);
#elif defined(MSG_FASTOPEN) /* old Linux */
    if(Curl_conn_is_ssl(cf->conn, cf->sockindex))
      rc = connect(ctx->sock, &ctx->addr.curl_sa_addr, ctx->addr.addrlen);
    else
      rc = 0; /* Do nothing */
#endif
  }
  else {
    rc = connect(ctx->sock, &ctx->addr.curl_sa_addr,
                 (curl_socklen_t)ctx->addr.addrlen);
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

  *done = FALSE; /* a negative world view is best */
  if(ctx->sock == CURL_SOCKET_BAD) {
    int error;

    result = cf_socket_open(cf, data);
    if(result)
      goto out;

    if(cf->connected) {
      *done = TRUE;
      return CURLE_OK;
    }

    /* Connect TCP socket */
    rc = do_connect(cf, data, cf->conn->bits.tcp_fastopen);
    error = SOCKERRNO;
    set_local_ip(cf, data);
    CURL_TRC_CF(data, cf, "local address %s port %d...",
                ctx->ip.local_ip, ctx->ip.local_port);
    if(-1 == rc) {
      result = socket_connect_result(data, ctx->ip.remote_ip, error);
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
      set_local_ip(cf, data);
      data->state.os_errno = ctx->error;
      SET_SOCKERRNO(ctx->error);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
      {
        char buffer[STRERROR_LEN];
        infof(data, "connect to %s port %u from %s port %d failed: %s",
              ctx->ip.remote_ip, ctx->ip.remote_port,
              ctx->ip.local_ip, ctx->ip.local_port,
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
  struct cf_socket_ctx *ctx = cf->ctx;
  (void)data;
  *phost = cf->conn->host.name;
  *pdisplay_host = cf->conn->host.dispname;
  *pport = ctx->ip.remote_port;
}

static void cf_socket_adjust_pollset(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct easy_pollset *ps)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  if(ctx->sock != CURL_SOCKET_BAD) {
    /* A listening socket filter needs to be connected before the accept
     * for some weird FTP interaction. This should be rewritten, so that
     * FTP no longer does the socket checks and accept calls and delegates
     * all that to the filter. TODO. */
    if(ctx->listening) {
      Curl_pollset_set_in_only(data, ps, ctx->sock);
      CURL_TRC_CF(data, cf, "adjust_pollset, listening, POLLIN fd=%"
                  FMT_SOCKET_T, ctx->sock);
    }
    else if(!cf->connected) {
      Curl_pollset_set_out_only(data, ps, ctx->sock);
      CURL_TRC_CF(data, cf, "adjust_pollset, !connected, POLLOUT fd=%"
                  FMT_SOCKET_T, ctx->sock);
    }
    else if(!ctx->active) {
      Curl_pollset_add_in(data, ps, ctx->sock);
      CURL_TRC_CF(data, cf, "adjust_pollset, !active, POLLIN fd=%"
                  FMT_SOCKET_T, ctx->sock);
    }
  }
}

static bool cf_socket_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  int readable;

  (void)data;
  readable = SOCKET_READABLE(ctx->sock, 0);
  return readable > 0 && (readable & CURL_CSELECT_IN);
}

#ifdef USE_WINSOCK

#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747B
#endif

static void win_update_sndbuf_size(struct cf_socket_ctx *ctx)
{
  ULONG ideal;
  DWORD ideallen;
  struct curltime n = Curl_now();

  if(Curl_timediff(n, ctx->last_sndbuf_query_at) > 1000) {
    if(!WSAIoctl(ctx->sock, SIO_IDEAL_SEND_BACKLOG_QUERY, 0, 0,
                  &ideal, sizeof(ideal), &ideallen, 0, 0) &&
       ideal != ctx->sndbuf_size &&
       !setsockopt(ctx->sock, SOL_SOCKET, SO_SNDBUF,
                   (const char *)&ideal, sizeof(ideal))) {
      ctx->sndbuf_size = ideal;
    }
    ctx->last_sndbuf_query_at = n;
  }
}

#endif /* USE_WINSOCK */

static ssize_t cf_socket_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *buf, size_t len, bool eos,
                              CURLcode *err)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  curl_socket_t fdsave;
  ssize_t nwritten;
  size_t orig_len = len;

  (void)eos; /* unused */
  *err = CURLE_OK;
  fdsave = cf->conn->sock[cf->sockindex];
  cf->conn->sock[cf->sockindex] = ctx->sock;

#ifdef DEBUGBUILD
  /* simulate network blocking/partial writes */
  if(ctx->wblock_percent > 0) {
    unsigned char c = 0;
    Curl_rand_bytes(data, FALSE, &c, 1);
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
                      &cf->conn->remote_addr->curl_sa_addr,
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

#if defined(USE_WINSOCK)
  if(!*err)
    win_update_sndbuf_size(ctx);
#endif

  CURL_TRC_CF(data, cf, "send(len=%zu) -> %d, err=%d",
              orig_len, (int)nwritten, *err);
  cf->conn->sock[cf->sockindex] = fdsave;
  return nwritten;
}

static ssize_t cf_socket_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t len, CURLcode *err)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  ssize_t nread;

  *err = CURLE_OK;

#ifdef DEBUGBUILD
  /* simulate network blocking/partial reads */
  if(cf->cft != &Curl_cft_udp && ctx->rblock_percent > 0) {
    unsigned char c = 0;
    Curl_rand(data, &c, 1);
    if(c >= ((100-ctx->rblock_percent)*256/100)) {
      CURL_TRC_CF(data, cf, "recv(len=%zu) SIMULATE EWOULDBLOCK", len);
      *err = CURLE_AGAIN;
      return -1;
    }
  }
  if(cf->cft != &Curl_cft_udp && ctx->recv_max && ctx->recv_max < len) {
    size_t orig_len = len;
    len = ctx->recv_max;
    CURL_TRC_CF(data, cf, "recv(len=%zu) SIMULATE max read of %zu bytes",
                orig_len, len);
  }
#endif

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
    }
    else {
      char buffer[STRERROR_LEN];

      failf(data, "Recv failure: %s",
            Curl_strerror(sockerr, buffer, sizeof(buffer)));
      data->state.os_errno = sockerr;
      *err = CURLE_RECV_ERROR;
    }
  }

  CURL_TRC_CF(data, cf, "recv(len=%zu) -> %d, err=%d", len, (int)nread,
              *err);
  if(nread > 0 && !ctx->got_first_byte) {
    ctx->first_byte_at = Curl_now();
    ctx->got_first_byte = TRUE;
  }
  return nread;
}

static void cf_socket_update_data(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  /* Update the IP info held in the transfer, if we have that. */
  if(cf->connected && (cf->sockindex == FIRSTSOCKET)) {
    struct cf_socket_ctx *ctx = cf->ctx;
    data->info.primary = ctx->ip;
    /* not sure if this is redundant... */
    data->info.conn_remote_port = cf->conn->remote_port;
  }
}

static void cf_socket_active(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;

  /* use this socket from now on */
  cf->conn->sock[cf->sockindex] = ctx->sock;
  set_local_ip(cf, data);
  if(cf->sockindex == FIRSTSOCKET) {
    cf->conn->primary = ctx->ip;
    cf->conn->remote_addr = &ctx->addr;
  #ifdef USE_IPV6
    cf->conn->bits.ipv6 = (ctx->addr.family == AF_INET6);
  #endif
  }
  else {
    cf->conn->secondary = ctx->ip;
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
    cf_socket_update_data(cf, data);
    break;
  case CF_CTRL_DATA_SETUP:
    cf_socket_update_data(cf, data);
    break;
  case CF_CTRL_FORGET_SOCKET:
    ctx->sock = CURL_SOCKET_BAD;
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
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
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
      FALLTHROUGH();
    default:
      *when = ctx->connected_at;
      break;
    }
    return CURLE_OK;
  }
  case CF_QUERY_IP_INFO:
#ifdef USE_IPV6
    *pres1 = (ctx->addr.family == AF_INET6);
#else
    *pres1 = FALSE;
#endif
    *(struct ip_quadruple *)pres2 = ctx->ip;
    return CURLE_OK;
  default:
    break;
  }
  return cf->next ?
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
  cf_socket_shutdown,
  cf_socket_get_host,
  cf_socket_adjust_pollset,
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
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_socket_ctx_init(ctx, ai, transport);
  if(result)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_tcp, ctx);

out:
  *pcf = (!result) ? cf : NULL;
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
  int one = 1;

  (void)one;

  /* QUIC needs a connected socket, nonblocking */
  DEBUGASSERT(ctx->sock != CURL_SOCKET_BAD);

  rc = connect(ctx->sock, &ctx->addr.curl_sa_addr,  /* NOLINT FIXME */
               (curl_socklen_t)ctx->addr.addrlen);
  if(-1 == rc) {
    return socket_connect_result(data, ctx->ip.remote_ip, SOCKERRNO);
  }
  ctx->sock_connected = TRUE;
  set_local_ip(cf, data);
  CURL_TRC_CF(data, cf, "%s socket %" FMT_SOCKET_T
              " connected: [%s:%d] -> [%s:%d]",
              (ctx->transport == TRNSPRT_QUIC) ? "QUIC" : "UDP",
              ctx->sock, ctx->ip.local_ip, ctx->ip.local_port,
              ctx->ip.remote_ip, ctx->ip.remote_port);

  /* Currently, cf->ctx->sock is always non-blocking because the only
   * caller to cf_udp_setup_quic() is cf_udp_connect() that passes the
   * non-blocking socket created by cf_socket_open() to it. Thus, we
   * do not need to call curlx_nonblock() in cf_udp_setup_quic() anymore.
   */
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

#if defined(__linux__) && defined(UDP_GRO) &&                                 \
  (defined(HAVE_SENDMMSG) || defined(HAVE_SENDMSG)) &&                        \
  ((defined(USE_NGTCP2) && defined(USE_NGHTTP3)) || defined(USE_QUICHE))
  (void)setsockopt(ctx->sock, IPPROTO_UDP, UDP_GRO, &one,
                   (socklen_t)sizeof(one));
#endif

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
                  FMT_SOCKET_T " (%s:%d)",
                  ctx->sock, ctx->ip.local_ip, ctx->ip.local_port);
    }
    else {
      CURL_TRC_CF(data, cf, "cf_udp_connect(), opened socket=%"
                  FMT_SOCKET_T " (unconnected)", ctx->sock);
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
  cf_socket_shutdown,
  cf_socket_get_host,
  cf_socket_adjust_pollset,
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
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_socket_ctx_init(ctx, ai, transport);
  if(result)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_udp, ctx);

out:
  *pcf = (!result) ? cf : NULL;
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
  cf_socket_shutdown,
  cf_socket_get_host,
  cf_socket_adjust_pollset,
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
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_socket_ctx_init(ctx, ai, transport);
  if(result)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_unix, ctx);

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

static timediff_t cf_tcp_accept_timeleft(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
  timediff_t timeout_ms = DEFAULT_ACCEPT_TIMEOUT;
  timediff_t other;
  struct curltime now;

#ifndef CURL_DISABLE_FTP
  if(data->set.accepttimeout > 0)
    timeout_ms = data->set.accepttimeout;
#endif

  now = Curl_now();
  /* check if the generic timeout possibly is set shorter */
  other = Curl_timeleft(data, &now, FALSE);
  if(other && (other < timeout_ms))
    /* note that this also works fine for when other happens to be negative
       due to it already having elapsed */
    timeout_ms = other;
  else {
    /* subtract elapsed time */
    timeout_ms -= Curl_timediff(now, ctx->started_at);
    if(!timeout_ms)
      /* avoid returning 0 as that means no timeout! */
      timeout_ms = -1;
  }
  return timeout_ms;
}

static void cf_tcp_set_accepted_remote_ip(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_socket_ctx *ctx = cf->ctx;
#ifdef HAVE_GETPEERNAME
  char buffer[STRERROR_LEN];
  struct Curl_sockaddr_storage ssrem;
  curl_socklen_t plen;

  ctx->ip.remote_ip[0] = 0;
  ctx->ip.remote_port = 0;
  plen = sizeof(ssrem);
  memset(&ssrem, 0, plen);
  if(getpeername(ctx->sock, (struct sockaddr*) &ssrem, &plen)) {
    int error = SOCKERRNO;
    failf(data, "getpeername() failed with errno %d: %s",
          error, Curl_strerror(error, buffer, sizeof(buffer)));
    return;
  }
  if(!Curl_addr2string((struct sockaddr*)&ssrem, plen,
                       ctx->ip.remote_ip, &ctx->ip.remote_port)) {
    failf(data, "ssrem inet_ntop() failed with errno %d: %s",
          errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    return;
  }
#else
  ctx->ip.remote_ip[0] = 0;
  ctx->ip.remote_port = 0;
  (void)data;
#endif
}

static CURLcode cf_tcp_accept_connect(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool blocking, bool *done)
{
  struct cf_socket_ctx *ctx = cf->ctx;
#ifdef USE_IPV6
  struct Curl_sockaddr_storage add;
#else
  struct sockaddr_in add;
#endif
  curl_socklen_t size = (curl_socklen_t) sizeof(add);
  curl_socket_t s_accepted = CURL_SOCKET_BAD;
  timediff_t timeout_ms;
  int socketstate = 0;
  bool incoming = FALSE;

  /* we start accepted, if we ever close, we cannot go on */
  (void)data;
  (void)blocking;
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  timeout_ms = cf_tcp_accept_timeleft(cf, data);
  if(timeout_ms < 0) {
    /* if a timeout was already reached, bail out */
    failf(data, "Accept timeout occurred while waiting server connect");
    return CURLE_FTP_ACCEPT_TIMEOUT;
  }

  CURL_TRC_CF(data, cf, "Checking for incoming on fd=%" FMT_SOCKET_T
              " ip=%s:%d", ctx->sock, ctx->ip.local_ip, ctx->ip.local_port);
  socketstate = Curl_socket_check(ctx->sock, CURL_SOCKET_BAD,
                                  CURL_SOCKET_BAD, 0);
  CURL_TRC_CF(data, cf, "socket_check -> %x", socketstate);
  switch(socketstate) {
  case -1: /* error */
    /* let's die here */
    failf(data, "Error while waiting for server connect");
    return CURLE_FTP_ACCEPT_FAILED;
  default:
    if(socketstate & CURL_CSELECT_IN) {
      infof(data, "Ready to accept data connection from server");
      incoming = TRUE;
    }
    break;
  }

  if(!incoming) {
    CURL_TRC_CF(data, cf, "nothing heard from the server yet");
    *done = FALSE;
    return CURLE_OK;
  }

  if(0 == getsockname(ctx->sock, (struct sockaddr *) &add, &size)) {
    size = sizeof(add);
    s_accepted = accept(ctx->sock, (struct sockaddr *) &add, &size);
  }

  if(CURL_SOCKET_BAD == s_accepted) {
    failf(data, "Error accept()ing server connect");
    return CURLE_FTP_PORT_FAILED;
  }

  infof(data, "Connection accepted from server");
  (void)curlx_nonblock(s_accepted, TRUE); /* enable non-blocking */
  /* Replace any filter on SECONDARY with one listening on this socket */
  ctx->listening = FALSE;
  ctx->accepted = TRUE;
  socket_close(data, cf->conn, TRUE, ctx->sock);
  ctx->sock = s_accepted;

  cf->conn->sock[cf->sockindex] = ctx->sock;
  cf_tcp_set_accepted_remote_ip(cf, data);
  set_local_ip(cf, data);
  ctx->active = TRUE;
  ctx->connected_at = Curl_now();
  cf->connected = TRUE;
  CURL_TRC_CF(data, cf, "accepted_set(sock=%" FMT_SOCKET_T
              ", remote=%s port=%d)",
              ctx->sock, ctx->ip.remote_ip, ctx->ip.remote_port);

  if(data->set.fsockopt) {
    int error = 0;

    /* activate callback for setting socket options */
    Curl_set_in_callback(data, true);
    error = data->set.fsockopt(data->set.sockopt_client,
                               ctx->sock, CURLSOCKTYPE_ACCEPT);
    Curl_set_in_callback(data, false);

    if(error)
      return CURLE_ABORTED_BY_CALLBACK;
  }
  return CURLE_OK;
}

struct Curl_cftype Curl_cft_tcp_accept = {
  "TCP-ACCEPT",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  cf_socket_destroy,
  cf_tcp_accept_connect,
  cf_socket_close,
  cf_socket_shutdown,
  cf_socket_get_host,              /* TODO: not accurate */
  cf_socket_adjust_pollset,
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

  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->transport = conn->transport;
  ctx->sock = *s;
  ctx->listening = TRUE;
  ctx->accepted = FALSE;
  result = Curl_cf_create(&cf, &Curl_cft_tcp_accept, ctx);
  if(result)
    goto out;
  Curl_conn_cf_add(data, conn, sockindex, cf);

  ctx->started_at = Curl_now();
  conn->sock[sockindex] = ctx->sock;
  set_local_ip(cf, data);
  CURL_TRC_CF(data, cf, "set filter for listen socket fd=%" FMT_SOCKET_T
              " ip=%s:%d", ctx->sock,
              ctx->ip.local_ip, ctx->ip.local_port);

out:
  if(result) {
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }
  return result;
}

bool Curl_conn_is_tcp_listen(struct Curl_easy *data,
                             int sockindex)
{
  struct Curl_cfilter *cf = data->conn->cfilter[sockindex];
  while(cf) {
    if(cf->cft == &Curl_cft_tcp_accept)
      return TRUE;
    cf = cf->next;
  }
  return FALSE;
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
                             struct ip_quadruple *pip)
{
  (void)data;
  if(cf_is_socket(cf) && cf->ctx) {
    struct cf_socket_ctx *ctx = cf->ctx;

    if(psock)
      *psock = ctx->sock;
    if(paddr)
      *paddr = &ctx->addr;
    if(pip)
      *pip = ctx->ip;
    return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}
