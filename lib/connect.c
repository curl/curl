/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* <netinet/tcp.h> may need it */
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h> /* for TCP_NODELAY */
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

#if (defined(HAVE_IOCTL_FIONBIO) && defined(NETWARE))
#include <sys/filio.h>
#endif
#ifdef NETWARE
#undef in_addr_t
#define in_addr_t unsigned long
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"
#include "strerror.h"
#include "connect.h"
#include "curl_memory.h"
#include "select.h"
#include "url.h" /* for Curl_safefree() */
#include "multiif.h"
#include "sockaddr.h" /* required for Curl_sockaddr_storage */
#include "inet_ntop.h"
#include "inet_pton.h"
#include "vtls/vtls.h" /* for Curl_ssl_check_cxn() */
#include "progress.h"
#include "warnless.h"
#include "conncache.h"
#include "multihandle.h"

/* The last #include file should be: */
#include "memdebug.h"

#ifdef __SYMBIAN32__
/* This isn't actually supported under Symbian OS */
#undef SO_NOSIGPIPE
#endif

static bool verifyconnect(curl_socket_t sockfd, int *error);

#if defined(__DragonFly__) || defined(HAVE_WINSOCK_H)
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
tcpkeepalive(struct SessionHandle *data,
             curl_socket_t sockfd)
{
  int optval = data->set.tcp_keepalive?1:0;

  /* only set IDLE and INTVL if setting KEEPALIVE is successful */
  if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE,
        (void *)&optval, sizeof(optval)) < 0) {
    infof(data, "Failed to set SO_KEEPALIVE on fd %d\n", sockfd);
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
      infof(data, "Failed to set SIO_KEEPALIVE_VALS on fd %d: %d\n",
            (int)sockfd, WSAGetLastError());
    }
#else
#ifdef TCP_KEEPIDLE
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPIDLE on fd %d\n", sockfd);
    }
#endif
#ifdef TCP_KEEPINTVL
    optval = curlx_sltosi(data->set.tcp_keepintvl);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPINTVL on fd %d\n", sockfd);
    }
#endif
#ifdef TCP_KEEPALIVE
    /* Mac OS X style */
    optval = curlx_sltosi(data->set.tcp_keepidle);
    KEEPALIVE_FACTOR(optval);
    if(setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE,
          (void *)&optval, sizeof(optval)) < 0) {
      infof(data, "Failed to set TCP_KEEPALIVE on fd %d\n", sockfd);
    }
#endif
#endif
  }
}

static CURLcode
singleipconnect(struct connectdata *conn,
                const Curl_addrinfo *ai, /* start connecting to this */
                curl_socket_t *sock);

/*
 * Curl_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is negative, the timeout time has already
 * elapsed.
 *
 * The start time is stored in progress.t_startsingle - as set with
 * Curl_pgrsTime(..., TIMER_STARTSINGLE);
 *
 * If 'nowp' is non-NULL, it points to the current time.
 * 'duringconnect' is FALSE if not during a connect, as then of course the
 * connect timeout is not taken into account!
 *
 * @unittest: 1303
 */
long Curl_timeleft(struct SessionHandle *data,
                   struct timeval *nowp,
                   bool duringconnect)
{
  int timeout_set = 0;
  long timeout_ms = duringconnect?DEFAULT_CONNECT_TIMEOUT:0;
  struct timeval now;

  /* if a timeout is set, use the most restrictive one */

  if(data->set.timeout > 0)
    timeout_set |= 1;
  if(duringconnect && (data->set.connecttimeout > 0))
    timeout_set |= 2;

  switch (timeout_set) {
  case 1:
    timeout_ms = data->set.timeout;
    break;
  case 2:
    timeout_ms = data->set.connecttimeout;
    break;
  case 3:
    if(data->set.timeout < data->set.connecttimeout)
      timeout_ms = data->set.timeout;
    else
      timeout_ms = data->set.connecttimeout;
    break;
  default:
    /* use the default */
    if(!duringconnect)
      /* if we're not during connect, there's no default timeout so if we're
         at zero we better just return zero and not make it a negative number
         by the math below */
      return 0;
    break;
  }

  if(!nowp) {
    now = Curl_tvnow();
    nowp = &now;
  }

  /* subtract elapsed time */
  if(duringconnect)
    /* since this most recent connect started */
    timeout_ms -= Curl_tvdiff(*nowp, data->progress.t_startsingle);
  else
    /* since the entire operation started */
    timeout_ms -= Curl_tvdiff(*nowp, data->progress.t_startop);
  if(!timeout_ms)
    /* avoid returning 0 as that means no timeout! */
    return -1;

  return timeout_ms;
}

static CURLcode bindlocal(struct connectdata *conn,
                          curl_socket_t sockfd, int af, unsigned int scope)
{
  struct SessionHandle *data = conn->data;

  struct Curl_sockaddr_storage sa;
  struct sockaddr *sock = (struct sockaddr *)&sa;  /* bind to this address */
  curl_socklen_t sizeof_sa = 0; /* size of the data sock points to */
  struct sockaddr_in *si4 = (struct sockaddr_in *)&sa;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&sa;
#endif

  struct Curl_dns_entry *h=NULL;
  unsigned short port = data->set.localport; /* use this port number, 0 for
                                                "random" */
  /* how many port numbers to try to bind to, increasing one at a time */
  int portnum = data->set.localportrange;
  const char *dev = data->set.str[STRING_DEVICE];
  int error;

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
      switch(Curl_if2ip(af, scope, conn->scope_id, dev,
                        myhost, sizeof(myhost))) {
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
          infof(data, "Local Interface %s is ip %s using address family %i\n",
                dev, myhost, af);
          done = 1;

#ifdef SO_BINDTODEVICE
          /* I am not sure any other OSs than Linux that provide this feature,
           * and at the least I cannot test. --Ben
           *
           * This feature allows one to tightly bind the local socket to a
           * particular interface.  This will force even requests to other
           * local interfaces to go out the external interface.
           *
           *
           * Only bind to the interface when specified as interface, not just
           * as a hostname or ip address.
           */
          if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                        dev, (curl_socklen_t)strlen(dev)+1) != 0) {
            error = SOCKERRNO;
            infof(data, "SO_BINDTODEVICE %s failed with errno %d: %s;"
                  " will do regular bind\n",
                  dev, error, Curl_strerror(conn, error));
            /* This is typically "errno 1, error: Operation not permitted" if
               you're not running as root or another suitable privileged
               user */
          }
#endif
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
      long ipver = conn->ip_version;
      int rc;

      if(af == AF_INET)
        conn->ip_version = CURL_IPRESOLVE_V4;
#ifdef ENABLE_IPV6
      else if(af == AF_INET6)
        conn->ip_version = CURL_IPRESOLVE_V6;
#endif

      rc = Curl_resolv(conn, dev, 0, &h);
      if(rc == CURLRESOLV_PENDING)
        (void)Curl_resolver_wait_resolv(conn, &h);
      conn->ip_version = ipver;

      if(h) {
        /* convert the resolved address, sizeof myhost >= INET_ADDRSTRLEN */
        Curl_printable_address(h->addr, myhost, sizeof(myhost));
        infof(data, "Name '%s' family %i resolved to '%s' family %i\n",
              dev, af, myhost, h->addr->ai_family);
        Curl_resolv_unlock(data, h);
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
          *(scope_ptr++) = 0;
#endif
        if(Curl_inet_pton(AF_INET6, myhost, &si6->sin6_addr) > 0) {
          si6->sin6_family = AF_INET6;
          si6->sin6_port = htons(port);
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
          if(scope_ptr)
            /* The "myhost" string either comes from Curl_if2ip or from
               Curl_printable_address. The latter returns only numeric scope
               IDs and the former returns none at all.  So the scope ID, if
               present, is known to be numeric */
            si6->sin6_scope_id = atoi(scope_ptr);
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

  for(;;) {
    if(bind(sockfd, sock, sizeof_sa) >= 0) {
      /* we succeeded to bind */
      struct Curl_sockaddr_storage add;
      curl_socklen_t size = sizeof(add);
      memset(&add, 0, sizeof(struct Curl_sockaddr_storage));
      if(getsockname(sockfd, (struct sockaddr *) &add, &size) < 0) {
        data->state.os_errno = error = SOCKERRNO;
        failf(data, "getsockname() failed with errno %d: %s",
              error, Curl_strerror(conn, error));
        return CURLE_INTERFACE_FAILED;
      }
      infof(data, "Local port: %hu\n", port);
      conn->bits.bound = TRUE;
      return CURLE_OK;
    }

    if(--portnum > 0) {
      infof(data, "Bind to local port %hu failed, trying next\n", port);
      port++; /* try next port */
      /* We re-use/clobber the port variable here below */
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

  data->state.os_errno = error = SOCKERRNO;
  failf(data, "bind failed with errno %d: %s",
        error, Curl_strerror(conn, error));

  return CURLE_INTERFACE_FAILED;
}

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
#ifdef __minix
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

/* Used within the multi interface. Try next IP address, return TRUE if no
   more address exists or error */
static CURLcode trynextip(struct connectdata *conn,
                          int sockindex,
                          int tempindex)
{
  const int other = tempindex ^ 1;
  CURLcode result = CURLE_COULDNT_CONNECT;

  /* First clean up after the failed socket.
     Don't close it yet to ensure that the next IP's socket gets a different
     file descriptor, which can prevent bugs when the curl_multi_socket_action
     interface is used with certain select() replacements such as kqueue. */
  curl_socket_t fd_to_close = conn->tempsock[tempindex];
  conn->tempsock[tempindex] = CURL_SOCKET_BAD;

  if(sockindex == FIRSTSOCKET) {
    Curl_addrinfo *ai = NULL;
    int family = AF_UNSPEC;

    if(conn->tempaddr[tempindex]) {
      /* find next address in the same protocol family */
      family = conn->tempaddr[tempindex]->ai_family;
      ai = conn->tempaddr[tempindex]->ai_next;
    }
    else if(conn->tempaddr[0]) {
      /* happy eyeballs - try the other protocol family */
      int firstfamily = conn->tempaddr[0]->ai_family;
#ifdef ENABLE_IPV6
      family = (firstfamily == AF_INET) ? AF_INET6 : AF_INET;
#else
      family = firstfamily;
#endif
      ai = conn->tempaddr[0]->ai_next;
    }

    while(ai) {
      if(conn->tempaddr[other]) {
        /* we can safely skip addresses of the other protocol family */
        while(ai && ai->ai_family != family)
          ai = ai->ai_next;
      }

      if(ai) {
        result = singleipconnect(conn, ai, &conn->tempsock[tempindex]);
        if(result == CURLE_COULDNT_CONNECT) {
          ai = ai->ai_next;
          continue;
        }

        conn->tempaddr[tempindex] = ai;
      }
      break;
    }
  }

  if(fd_to_close != CURL_SOCKET_BAD)
    Curl_closesocket(conn, fd_to_close);

  return result;
}

/* Copies connection info into the session handle to make it available
   when the session handle is no longer associated with a connection. */
void Curl_persistconninfo(struct connectdata *conn)
{
  memcpy(conn->data->info.conn_primary_ip, conn->primary_ip, MAX_IPADR_LEN);
  memcpy(conn->data->info.conn_local_ip, conn->local_ip, MAX_IPADR_LEN);
  conn->data->info.conn_primary_port = conn->primary_port;
  conn->data->info.conn_local_port = conn->local_port;
}

/* retrieves ip address and port from a sockaddr structure */
static bool getaddressinfo(struct sockaddr* sa, char* addr,
                           long* port)
{
  unsigned short us_port;
  struct sockaddr_in* si = NULL;
#ifdef ENABLE_IPV6
  struct sockaddr_in6* si6 = NULL;
#endif
#if defined(HAVE_SYS_UN_H) && defined(AF_UNIX)
  struct sockaddr_un* su = NULL;
#endif

  switch (sa->sa_family) {
    case AF_INET:
      si = (struct sockaddr_in*) sa;
      if(Curl_inet_ntop(sa->sa_family, &si->sin_addr,
                        addr, MAX_IPADR_LEN)) {
        us_port = ntohs(si->sin_port);
        *port = us_port;
        return TRUE;
      }
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      si6 = (struct sockaddr_in6*)sa;
      if(Curl_inet_ntop(sa->sa_family, &si6->sin6_addr,
                        addr, MAX_IPADR_LEN)) {
        us_port = ntohs(si6->sin6_port);
        *port = us_port;
        return TRUE;
      }
      break;
#endif
#if defined(HAVE_SYS_UN_H) && defined(AF_UNIX)
    case AF_UNIX:
      su = (struct sockaddr_un*)sa;
      snprintf(addr, MAX_IPADR_LEN, "%s", su->sun_path);
      *port = 0;
      return TRUE;
#endif
    default:
      break;
  }

  addr[0] = '\0';
  *port = 0;

  return FALSE;
}

/* retrieves the start/end point information of a socket of an established
   connection */
void Curl_updateconninfo(struct connectdata *conn, curl_socket_t sockfd)
{
  curl_socklen_t len;
  struct Curl_sockaddr_storage ssrem;
  struct Curl_sockaddr_storage ssloc;
  struct SessionHandle *data = conn->data;

  if(conn->socktype == SOCK_DGRAM)
    /* there's no connection! */
    return;

  if(!conn->bits.reuse) {
    int error;

    len = sizeof(struct Curl_sockaddr_storage);
    if(getpeername(sockfd, (struct sockaddr*) &ssrem, &len)) {
      error = SOCKERRNO;
      failf(data, "getpeername() failed with errno %d: %s",
            error, Curl_strerror(conn, error));
      return;
    }

    len = sizeof(struct Curl_sockaddr_storage);
    memset(&ssloc, 0, sizeof(ssloc));
    if(getsockname(sockfd, (struct sockaddr*) &ssloc, &len)) {
      error = SOCKERRNO;
      failf(data, "getsockname() failed with errno %d: %s",
            error, Curl_strerror(conn, error));
      return;
    }

    if(!getaddressinfo((struct sockaddr*)&ssrem,
                        conn->primary_ip, &conn->primary_port)) {
      error = ERRNO;
      failf(data, "ssrem inet_ntop() failed with errno %d: %s",
            error, Curl_strerror(conn, error));
      return;
    }
    memcpy(conn->ip_addr_str, conn->primary_ip, MAX_IPADR_LEN);

    if(!getaddressinfo((struct sockaddr*)&ssloc,
                       conn->local_ip, &conn->local_port)) {
      error = ERRNO;
      failf(data, "ssloc inet_ntop() failed with errno %d: %s",
            error, Curl_strerror(conn, error));
      return;
    }

  }

  /* persist connection info in session handle */
  Curl_persistconninfo(conn);
}

/*
 * Curl_is_connected() checks if the socket has connected.
 */

CURLcode Curl_is_connected(struct connectdata *conn,
                           int sockindex,
                           bool *connected)
{
  struct SessionHandle *data = conn->data;
  CURLcode result = CURLE_OK;
  long allow;
  int error = 0;
  struct timeval now;
  int rc;
  int i;

  DEBUGASSERT(sockindex >= FIRSTSOCKET && sockindex <= SECONDARYSOCKET);

  *connected = FALSE; /* a very negative world view is best */

  if(conn->bits.tcpconnect[sockindex]) {
    /* we are connected already! */
    *connected = TRUE;
    return CURLE_OK;
  }

  now = Curl_tvnow();

  /* figure out how long time we have left to connect */
  allow = Curl_timeleft(data, &now, TRUE);

  if(allow < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  for(i=0; i<2; i++) {
    const int other = i ^ 1;
    if(conn->tempsock[i] == CURL_SOCKET_BAD)
      continue;

#ifdef mpeix
    /* Call this function once now, and ignore the results. We do this to
       "clear" the error state on the socket so that we can later read it
       reliably. This is reported necessary on the MPE/iX operating system. */
    (void)verifyconnect(conn->tempsock[i], NULL);
#endif

    /* check socket for connect */
    rc = Curl_socket_ready(CURL_SOCKET_BAD, conn->tempsock[i], 0);

    if(rc == 0) { /* no connection yet */
      if(curlx_tvdiff(now, conn->connecttime) >= conn->timeoutms_per_addr) {
        infof(data, "After %ldms connect time, move on!\n",
              conn->timeoutms_per_addr);
        error = ETIMEDOUT;
      }

      /* should we try another protocol family? */
      if(i == 0 && conn->tempaddr[1] == NULL &&
         curlx_tvdiff(now, conn->connecttime) >= HAPPY_EYEBALLS_TIMEOUT) {
        trynextip(conn, sockindex, 1);
      }
    }
    else if(rc == CURL_CSELECT_OUT) {
      if(verifyconnect(conn->tempsock[i], &error)) {
        /* we are connected with TCP, awesome! */

        /* use this socket from now on */
        conn->sock[sockindex] = conn->tempsock[i];
        conn->ip_addr = conn->tempaddr[i];
        conn->tempsock[i] = CURL_SOCKET_BAD;

        /* close the other socket, if open */
        if(conn->tempsock[other] != CURL_SOCKET_BAD) {
          Curl_closesocket(conn, conn->tempsock[other]);
          conn->tempsock[other] = CURL_SOCKET_BAD;
        }

        /* see if we need to do any proxy magic first once we connected */
        result = Curl_connected_proxy(conn, sockindex);
        if(result)
          return result;

        conn->bits.tcpconnect[sockindex] = TRUE;

        *connected = TRUE;
        if(sockindex == FIRSTSOCKET)
          Curl_pgrsTime(data, TIMER_CONNECT); /* connect done */
        Curl_updateconninfo(conn, conn->sock[sockindex]);
        Curl_verboseconnect(conn);

        return CURLE_OK;
      }
      else
        infof(data, "Connection failed\n");
    }
    else if(rc & CURL_CSELECT_ERR)
      (void)verifyconnect(conn->tempsock[i], &error);

    /*
     * The connection failed here, we should attempt to connect to the "next
     * address" for the given host. But first remember the latest error.
     */
    if(error) {
      data->state.os_errno = error;
      SET_SOCKERRNO(error);
      if(conn->tempaddr[i]) {
        CURLcode status;
        char ipaddress[MAX_IPADR_LEN];
        Curl_printable_address(conn->tempaddr[i], ipaddress, MAX_IPADR_LEN);
        infof(data, "connect to %s port %ld failed: %s\n",
              ipaddress, conn->port, Curl_strerror(conn, error));

        conn->timeoutms_per_addr = conn->tempaddr[i]->ai_next == NULL ?
                                   allow : allow / 2;

        status = trynextip(conn, sockindex, i);
        if(status != CURLE_COULDNT_CONNECT
            || conn->tempsock[other] == CURL_SOCKET_BAD)
          /* the last attempt failed and no other sockets remain open */
          result = status;
      }
    }
  }

  if(result) {
    /* no more addresses to try */

    /* if the first address family runs out of addresses to try before
       the happy eyeball timeout, go ahead and try the next family now */
    if(conn->tempaddr[1] == NULL) {
      result = trynextip(conn, sockindex, 1);
      if(!result)
        return result;
    }

    failf(data, "Failed to connect to %s port %ld: %s",
          conn->bits.proxy?conn->proxy.name:conn->host.name,
          conn->port, Curl_strerror(conn, error));
  }

  return result;
}

static void tcpnodelay(struct connectdata *conn,
                       curl_socket_t sockfd)
{
#ifdef TCP_NODELAY
  struct SessionHandle *data= conn->data;
  curl_socklen_t onoff = (curl_socklen_t) data->set.tcp_nodelay;
  int level = IPPROTO_TCP;

#if 0
  /* The use of getprotobyname() is disabled since it isn't thread-safe on
     numerous systems. On these getprotobyname_r() should be used instead, but
     that exists in at least one 4 arg version and one 5 arg version, and
     since the proto number rarely changes anyway we now just use the hard
     coded number. The "proper" fix would need a configure check for the
     correct function much in the same style the gethostbyname_r versions are
     detected. */
  struct protoent *pe = getprotobyname("tcp");
  if(pe)
    level = pe->p_proto;
#endif

  if(setsockopt(sockfd, level, TCP_NODELAY, (void *)&onoff,
                sizeof(onoff)) < 0)
    infof(data, "Could not set TCP_NODELAY: %s\n",
          Curl_strerror(conn, SOCKERRNO));
  else
    infof(data,"TCP_NODELAY set\n");
#else
  (void)conn;
  (void)sockfd;
#endif
}

#ifdef SO_NOSIGPIPE
/* The preferred method on Mac OS X (10.2 and later) to prevent SIGPIPEs when
   sending data to a dead peer (instead of relying on the 4th argument to send
   being MSG_NOSIGNAL). Possibly also existing and in use on other BSD
   systems? */
static void nosigpipe(struct connectdata *conn,
                      curl_socket_t sockfd)
{
  struct SessionHandle *data= conn->data;
  int onoff = 1;
  if(setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&onoff,
                sizeof(onoff)) < 0)
    infof(data, "Could not set SO_NOSIGPIPE: %s\n",
          Curl_strerror(conn, SOCKERRNO));
}
#else
#define nosigpipe(x,y) Curl_nop_stmt
#endif

#ifdef USE_WINSOCK
/* When you run a program that uses the Windows Sockets API, you may
   experience slow performance when you copy data to a TCP server.

   http://support.microsoft.com/kb/823764

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
  DWORD majorVersion = 6;

  static int detectOsState = DETECT_OS_NONE;

  if(detectOsState == DETECT_OS_NONE) {
#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
    (_WIN32_WINNT < _WIN32_WINNT_WIN2K)
    OSVERSIONINFO osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);

    detectOsState = DETECT_OS_PREVISTA;
    if(GetVersionEx(&osver)) {
      if(osver.dwMajorVersion >= majorVersion)
        detectOsState = DETECT_OS_VISTA_OR_LATER;
    }
#else
    ULONGLONG majorVersionMask;
    OSVERSIONINFOEX osver;

    memset(&osver, 0, sizeof(osver));
    osver.dwOSVersionInfoSize = sizeof(osver);
    osver.dwMajorVersion = majorVersion;
    majorVersionMask = VerSetConditionMask(0, VER_MAJORVERSION,
                                           VER_GREATER_EQUAL);

    if(VerifyVersionInfo(&osver, VER_MAJORVERSION, majorVersionMask))
      detectOsState = DETECT_OS_VISTA_OR_LATER;
    else
      detectOsState = DETECT_OS_PREVISTA;
#endif
  }

  if(detectOsState == DETECT_OS_VISTA_OR_LATER)
    return;

  if(getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&curval, &curlen) == 0)
    if(curval > val)
      return;

  setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (const char *)&val, sizeof(val));
}
#endif

/*
 * singleipconnect()
 *
 * Note that even on connect fail it returns CURLE_OK, but with 'sock' set to
 * CURL_SOCKET_BAD. Other errors will however return proper errors.
 *
 * singleipconnect() connects to the given IP only, and it may return without
 * having connected.
 */
static CURLcode singleipconnect(struct connectdata *conn,
                                const Curl_addrinfo *ai,
                                curl_socket_t *sockp)
{
  struct Curl_sockaddr_ex addr;
  int rc;
  int error = 0;
  bool isconnected = FALSE;
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd;
  CURLcode result;
  char ipaddress[MAX_IPADR_LEN];
  long port;
  bool is_tcp;

  *sockp = CURL_SOCKET_BAD;

  result = Curl_socket(conn, ai, &addr, &sockfd);
  if(result)
    /* Failed to create the socket, but still return OK since we signal the
       lack of socket as well. This allows the parent function to keep looping
       over alternative addresses/socket families etc. */
    return CURLE_OK;

  /* store remote address and port used in this connection attempt */
  if(!getaddressinfo((struct sockaddr*)&addr.sa_addr,
                     ipaddress, &port)) {
    /* malformed address or bug in inet_ntop, try next address */
    error = ERRNO;
    failf(data, "sa_addr inet_ntop() failed with errno %d: %s",
          error, Curl_strerror(conn, error));
    Curl_closesocket(conn, sockfd);
    return CURLE_OK;
  }
  infof(data, "  Trying %s...\n", ipaddress);

#ifdef ENABLE_IPV6
  is_tcp = (addr.family == AF_INET || addr.family == AF_INET6) &&
    addr.socktype == SOCK_STREAM;
#else
  is_tcp = (addr.family == AF_INET) && addr.socktype == SOCK_STREAM;
#endif
  if(is_tcp && data->set.tcp_nodelay)
    tcpnodelay(conn, sockfd);

  nosigpipe(conn, sockfd);

  Curl_sndbufset(sockfd);

  if(is_tcp && data->set.tcp_keepalive)
    tcpkeepalive(data, sockfd);

  if(data->set.fsockopt) {
    /* activate callback for setting socket options */
    error = data->set.fsockopt(data->set.sockopt_client,
                               sockfd,
                               CURLSOCKTYPE_IPCXN);

    if(error == CURL_SOCKOPT_ALREADY_CONNECTED)
      isconnected = TRUE;
    else if(error) {
      Curl_closesocket(conn, sockfd); /* close the socket and bail out */
      return CURLE_ABORTED_BY_CALLBACK;
    }
  }

  /* possibly bind the local end to an IP, interface or port */
  if(addr.family == AF_INET
#ifdef ENABLE_IPV6
     || addr.family == AF_INET6
#endif
    ) {
    result = bindlocal(conn, sockfd, addr.family,
                       Curl_ipv6_scope((struct sockaddr*)&addr.sa_addr));
    if(result) {
      Curl_closesocket(conn, sockfd); /* close socket and bail out */
      if(result == CURLE_UNSUPPORTED_PROTOCOL) {
        /* The address family is not supported on this interface.
           We can continue trying addresses */
        return CURLE_COULDNT_CONNECT;
      }
      return result;
    }
  }

  /* set socket non-blocking */
  (void)curlx_nonblock(sockfd, TRUE);

  conn->connecttime = Curl_tvnow();
  if(conn->num_addr > 1)
    Curl_expire_latest(data, conn->timeoutms_per_addr);

  /* Connect TCP sockets, bind UDP */
  if(!isconnected && (conn->socktype == SOCK_STREAM)) {
    rc = connect(sockfd, &addr.sa_addr, addr.addrlen);
    if(-1 == rc)
      error = SOCKERRNO;
  }
  else {
    *sockp = sockfd;
    return CURLE_OK;
  }

#ifdef ENABLE_IPV6
  conn->bits.ipv6 = (addr.family == AF_INET6)?TRUE:FALSE;
#endif

  if(-1 == rc) {
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
      result = CURLE_OK;
      break;

    default:
      /* unknown error, fallthrough and try another address! */
      infof(data, "Immediate connect fail for %s: %s\n",
            ipaddress, Curl_strerror(conn,error));
      data->state.os_errno = error;

      /* connect failed */
      Curl_closesocket(conn, sockfd);
      result = CURLE_COULDNT_CONNECT;
    }
  }

  if(!result)
    *sockp = sockfd;

  return result;
}

/*
 * TCP connect to the given host with timeout, proxy or remote doesn't matter.
 * There might be more than one IP address to try out. Fill in the passed
 * pointer with the connected socket.
 */

CURLcode Curl_connecthost(struct connectdata *conn,  /* context */
                          const struct Curl_dns_entry *remotehost)
{
  struct SessionHandle *data = conn->data;
  struct timeval before = Curl_tvnow();
  CURLcode result = CURLE_COULDNT_CONNECT;

  long timeout_ms = Curl_timeleft(data, &before, TRUE);

  if(timeout_ms < 0) {
    /* a precaution, no need to continue if time already is up */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  conn->num_addr = Curl_num_addresses(remotehost->addr);
  conn->tempaddr[0] = remotehost->addr;
  conn->tempaddr[1] = NULL;
  conn->tempsock[0] = CURL_SOCKET_BAD;
  conn->tempsock[1] = CURL_SOCKET_BAD;
  Curl_expire(conn->data, HAPPY_EYEBALLS_TIMEOUT);

  /* Max time for the next connection attempt */
  conn->timeoutms_per_addr =
    conn->tempaddr[0]->ai_next == NULL ? timeout_ms : timeout_ms / 2;

  /* start connecting to first IP */
  while(conn->tempaddr[0]) {
    result = singleipconnect(conn, conn->tempaddr[0], &(conn->tempsock[0]));
    if(!result)
      break;
    conn->tempaddr[0] = conn->tempaddr[0]->ai_next;
  }

  if(conn->tempsock[0] == CURL_SOCKET_BAD)
    return result;

  data->info.numconnects++; /* to track the number of connections made */

  return CURLE_OK;
}

struct connfind {
  struct connectdata *tofind;
  bool found;
};

static int conn_is_conn(struct connectdata *conn, void *param)
{
  struct connfind *f = (struct connfind *)param;
  if(conn == f->tofind) {
    f->found = TRUE;
    return 1;
  }
  return 0;
}

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given SessionHandle.
 *
 * The returned socket will be CURL_SOCKET_BAD in case of failure!
 */
curl_socket_t Curl_getconnectinfo(struct SessionHandle *data,
                                  struct connectdata **connp)
{
  curl_socket_t sockfd;

  DEBUGASSERT(data);

  /* this only works for an easy handle that has been used for
     curl_easy_perform()! */
  if(data->state.lastconnect && data->multi_easy) {
    struct connectdata *c = data->state.lastconnect;
    struct connfind find;
    find.tofind = data->state.lastconnect;
    find.found = FALSE;

    Curl_conncache_foreach(data->multi_easy->conn_cache, &find, conn_is_conn);

    if(!find.found) {
      data->state.lastconnect = NULL;
      return CURL_SOCKET_BAD;
    }

    if(connp)
      /* only store this if the caller cares for it */
      *connp = c;
    sockfd = c->sock[FIRSTSOCKET];
    /* we have a socket connected, let's determine if the server shut down */
    /* determine if ssl */
    if(c->ssl[FIRSTSOCKET].use) {
      /* use the SSL context */
      if(!Curl_ssl_check_cxn(c))
        return CURL_SOCKET_BAD;   /* FIN received */
    }
/* Minix 3.1 doesn't support any flags on recv; just assume socket is OK */
#ifdef MSG_PEEK
    else {
      /* use the socket */
      char buf;
      if(recv((RECV_TYPE_ARG1)c->sock[FIRSTSOCKET], (RECV_TYPE_ARG2)&buf,
              (RECV_TYPE_ARG3)1, (RECV_TYPE_ARG4)MSG_PEEK) == 0) {
        return CURL_SOCKET_BAD;   /* FIN received */
      }
    }
#endif
  }
  else
    return CURL_SOCKET_BAD;

  return sockfd;
}

/*
 * Close a socket.
 *
 * 'conn' can be NULL, beware!
 */
int Curl_closesocket(struct connectdata *conn,
                      curl_socket_t sock)
{
  if(conn && conn->fclosesocket) {
    if((sock == conn->sock[SECONDARYSOCKET]) &&
       conn->sock_accepted[SECONDARYSOCKET])
      /* if this socket matches the second socket, and that was created with
         accept, then we MUST NOT call the callback but clear the accepted
         status */
      conn->sock_accepted[SECONDARYSOCKET] = FALSE;
    else
      return conn->fclosesocket(conn->closesocket_client, sock);
  }

  if(conn)
    /* tell the multi-socket code about this */
    Curl_multi_closed(conn, sock);

  sclose(sock);

  return 0;
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
CURLcode Curl_socket(struct connectdata *conn,
                     const Curl_addrinfo *ai,
                     struct Curl_sockaddr_ex *addr,
                     curl_socket_t *sockfd)
{
  struct SessionHandle *data = conn->data;
  struct Curl_sockaddr_ex dummy;

  if(!addr)
    /* if the caller doesn't want info back, use a local temp copy */
    addr = &dummy;

  /*
   * The Curl_sockaddr_ex structure is basically libcurl's external API
   * curl_sockaddr structure with enough space available to directly hold
   * any protocol-specific address structures. The variable declared here
   * will be used to pass / receive data to/from the fopensocket callback
   * if this has been set, before that, it is initialized from parameters.
   */

  addr->family = ai->ai_family;
  addr->socktype = conn->socktype;
  addr->protocol = conn->socktype==SOCK_DGRAM?IPPROTO_UDP:ai->ai_protocol;
  addr->addrlen = ai->ai_addrlen;

  if(addr->addrlen > sizeof(struct Curl_sockaddr_storage))
     addr->addrlen = sizeof(struct Curl_sockaddr_storage);
  memcpy(&addr->sa_addr, ai->ai_addr, addr->addrlen);

  if(data->set.fopensocket)
   /*
    * If the opensocket callback is set, all the destination address
    * information is passed to the callback. Depending on this information the
    * callback may opt to abort the connection, this is indicated returning
    * CURL_SOCKET_BAD; otherwise it will return a not-connected socket. When
    * the callback returns a valid socket the destination address information
    * might have been changed and this 'new' address will actually be used
    * here to connect.
    */
    *sockfd = data->set.fopensocket(data->set.opensocket_client,
                                    CURLSOCKTYPE_IPCXN,
                                    (struct curl_sockaddr *)addr);
  else
    /* opensocket callback not set, so simply create the socket now */
    *sockfd = socket(addr->family, addr->socktype, addr->protocol);

  if(*sockfd == CURL_SOCKET_BAD)
    /* no socket, no connection */
    return CURLE_COULDNT_CONNECT;

#if defined(ENABLE_IPV6) && defined(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(conn->scope_id && (addr->family == AF_INET6)) {
    struct sockaddr_in6 * const sa6 = (void *)&addr->sa_addr;
    sa6->sin6_scope_id = conn->scope_id;
  }
#endif

  return CURLE_OK;

}

#ifdef CURLDEBUG
/*
 * Curl_conncontrol() is used to set the conn->bits.close bit on or off. It
 * MUST be called with the connclose() or connkeep() macros with a stated
 * reason. The reason is only shown in debug builds but helps to figure out
 * decision paths when connections are or aren't re-used as expected.
 */
void Curl_conncontrol(struct connectdata *conn, bool closeit,
                      const char *reason)
{
#if defined(CURL_DISABLE_VERBOSE_STRINGS)
  (void) reason;
#endif

  infof(conn->data, "Marked for [%s]: %s\n", closeit?"closure":"keep alive",
        reason);

  conn->bits.close = closeit; /* the only place in the source code that should
                                 assign this bit */
}
#endif
