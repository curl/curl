/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
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
#include "sslgen.h" /* for Curl_ssl_check_cxn() */
#include "progress.h"
#include "warnless.h"

/* The last #include file should be: */
#include "memdebug.h"

#ifdef __SYMBIAN32__
/* This isn't actually supported under Symbian OS */
#undef SO_NOSIGPIPE
#endif

struct Curl_sockaddr_ex {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  union {
    struct sockaddr addr;
    struct Curl_sockaddr_storage buff;
  } _sa_ex_u;
};
#define sa_addr _sa_ex_u.addr

static bool verifyconnect(curl_socket_t sockfd, int *error);

static CURLcode
singleipconnect(struct connectdata *conn,
                const Curl_addrinfo *ai, /* start connecting to this */
                long timeout_ms,
                curl_socket_t *sock,
                bool *connected);

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
  timeout_ms -= Curl_tvdiff(*nowp, data->progress.t_startsingle);
  if(!timeout_ms)
    /* avoid returning 0 as that means no timeout! */
    return -1;

  return timeout_ms;
}

/*
 * waitconnect() waits for a TCP connect on the given socket for the specified
 * number if milliseconds. It returns:
 */

#define WAITCONN_CONNECTED     0
#define WAITCONN_SELECT_ERROR -1
#define WAITCONN_TIMEOUT       1
#define WAITCONN_FDSET_ERROR   2
#define WAITCONN_ABORTED       3

static
int waitconnect(struct connectdata *conn,
                curl_socket_t sockfd, /* socket */
                long timeout_msec)
{
  int rc;
#ifdef mpeix
  /* Call this function once now, and ignore the results. We do this to
     "clear" the error state on the socket so that we can later read it
     reliably. This is reported necessary on the MPE/iX operating system. */
  (void)verifyconnect(sockfd, NULL);
#endif

  for(;;) {

    /* now select() until we get connect or timeout */
    rc = Curl_socket_ready(CURL_SOCKET_BAD, sockfd, timeout_msec>1000?
                           1000:timeout_msec);
    if(Curl_pgrsUpdate(conn))
      return WAITCONN_ABORTED;

    if(-1 == rc)
      /* error, no connect here, try next */
      return WAITCONN_SELECT_ERROR;

    else if(0 == rc) {
      /* timeout */
      timeout_msec -= 1000;
      if(timeout_msec <= 0)
        return WAITCONN_TIMEOUT;

      continue;
    }

    if(rc & CURL_CSELECT_ERR)
      /* error condition caught */
      return WAITCONN_FDSET_ERROR;

    break;
  }
  return WAITCONN_CONNECTED;
}

static CURLcode bindlocal(struct connectdata *conn,
                          curl_socket_t sockfd, int af)
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
  char myhost[256] = "";
  int done = 0; /* -1 for error, 1 for address found */

  /*************************************************************
   * Select device to bind socket to
   *************************************************************/
  if(!dev && !port)
    /* no local kind of binding was requested */
    return CURLE_OK;

  memset(&sa, 0, sizeof(struct Curl_sockaddr_storage));

  if(dev && (strlen(dev)<255) ) {

    /* interface */
    if(Curl_if2ip(af, dev, myhost, sizeof(myhost))) {
      /*
       * We now have the numerical IP address in the 'myhost' buffer
       */
      infof(data, "Local Interface %s is ip %s using address family %i\n",
            dev, myhost, af);
      done = 1;

#ifdef SO_BINDTODEVICE
      /* I am not sure any other OSs than Linux that provide this feature, and
       * at the least I cannot test. --Ben
       *
       * This feature allows one to tightly bind the local socket to a
       * particular interface.  This will force even requests to other local
       * interfaces to go out the external interface.
       *
       *
       * Only bind to the interface when specified as interface, not just as a
       * hostname or ip address.
       */
      if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                    dev, (curl_socklen_t)strlen(dev)+1) != 0) {
        error = SOCKERRNO;
        infof(data, "SO_BINDTODEVICE %s failed with errno %d: %s;"
              " will do regular bind\n",
              dev, error, Curl_strerror(conn, error));
        /* This is typically "errno 1, error: Operation not permitted" if
           you're not running as root or another suitable privileged user */
      }
#endif
    }
    else {
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
      /* ipv6 address */
      if((af == AF_INET6) &&
         (Curl_inet_pton(AF_INET6, myhost, &si6->sin6_addr) > 0)) {
        si6->sin6_family = AF_INET6;
        si6->sin6_port = htons(port);
        sizeof_sa = sizeof(struct sockaddr_in6);
      }
      else
#endif
      /* ipv4 address */
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
                          bool *connected)
{
  curl_socket_t sockfd;
  Curl_addrinfo *ai;

  /* First clean up after the failed socket.
     Don't close it yet to ensure that the next IP's socket gets a different
     file descriptor, which can prevent bugs when the curl_multi_socket_action
     interface is used with certain select() replacements such as kqueue. */
  curl_socket_t fd_to_close = conn->sock[sockindex];
  conn->sock[sockindex] = CURL_SOCKET_BAD;
  *connected = FALSE;

  if(sockindex != FIRSTSOCKET) {
    Curl_closesocket(conn, fd_to_close);
    return CURLE_COULDNT_CONNECT; /* no next */
  }

  /* try the next address */
  ai = conn->ip_addr->ai_next;

  while(ai) {
    CURLcode res = singleipconnect(conn, ai, 0L, &sockfd, connected);
    if(res)
      return res;
    if(sockfd != CURL_SOCKET_BAD) {
      /* store the new socket descriptor */
      conn->sock[sockindex] = sockfd;
      conn->ip_addr = ai;
      Curl_closesocket(conn, fd_to_close);
      return CURLE_OK;
    }
    ai = ai->ai_next;
  }
  Curl_closesocket(conn, fd_to_close);
  return CURLE_COULDNT_CONNECT;
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
  int error;
  curl_socklen_t len;
  struct Curl_sockaddr_storage ssrem;
  struct Curl_sockaddr_storage ssloc;
  struct SessionHandle *data = conn->data;

  if(!conn->bits.reuse) {

    len = sizeof(struct Curl_sockaddr_storage);
    if(getpeername(sockfd, (struct sockaddr*) &ssrem, &len)) {
      error = SOCKERRNO;
      failf(data, "getpeername() failed with errno %d: %s",
            error, Curl_strerror(conn, error));
      return;
    }

    len = sizeof(struct Curl_sockaddr_storage);
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
 * Curl_is_connected() is used from the multi interface to check if the
 * firstsocket has connected.
 */

CURLcode Curl_is_connected(struct connectdata *conn,
                           int sockindex,
                           bool *connected)
{
  int rc;
  struct SessionHandle *data = conn->data;
  CURLcode code = CURLE_OK;
  curl_socket_t sockfd = conn->sock[sockindex];
  long allow = DEFAULT_CONNECT_TIMEOUT;
  int error = 0;
  struct timeval now;

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

  /* check for connect without timeout as we want to return immediately */
  rc = waitconnect(conn, sockfd, 0);
  if(WAITCONN_TIMEOUT == rc) {
    if(curlx_tvdiff(now, conn->connecttime) >= conn->timeoutms_per_addr) {
      infof(data, "After %ldms connect time, move on!\n",
            conn->timeoutms_per_addr);
      goto next;
    }

    /* not an error, but also no connection yet */
    return code;
  }

  if(WAITCONN_CONNECTED == rc) {
    if(verifyconnect(sockfd, &error)) {
      /* we are connected with TCP, awesome! */

      /* see if we need to do any proxy magic first once we connected */
      code = Curl_connected_proxy(conn);
      if(code)
        return code;

      conn->bits.tcpconnect[sockindex] = TRUE;
      *connected = TRUE;
      if(sockindex == FIRSTSOCKET)
        Curl_pgrsTime(data, TIMER_CONNECT); /* connect done */
      Curl_verboseconnect(conn);
      Curl_updateconninfo(conn, sockfd);

      return CURLE_OK;
    }
    /* nope, not connected for real */
  }
  else {
    /* nope, not connected  */
    if(WAITCONN_FDSET_ERROR == rc) {
      (void)verifyconnect(sockfd, &error);
      infof(data, "%s\n",Curl_strerror(conn, error));
    }
    else
      infof(data, "Connection failed\n");
  }

  /*
   * The connection failed here, we should attempt to connect to the "next
   * address" for the given host. But first remember the latest error.
   */
  if(error) {
    data->state.os_errno = error;
    SET_SOCKERRNO(error);
  }
  next:

  code = trynextip(conn, sockindex, connected);

  if(code) {
    error = SOCKERRNO;
    data->state.os_errno = error;
    failf(data, "Failed connect to %s:%ld; %s",
          conn->host.name, conn->port, Curl_strerror(conn, error));
  }

  return code;
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

*/
void Curl_sndbufset(curl_socket_t sockfd)
{
  int val = CURL_MAX_WRITE_SIZE + 32;
  int curval = 0;
  int curlen = sizeof(curval);

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
 * having connected if used from the multi interface.
 */
static CURLcode
singleipconnect(struct connectdata *conn,
                const Curl_addrinfo *ai,
                long timeout_ms,
                curl_socket_t *sockp,
                bool *connected)
{
  struct Curl_sockaddr_ex addr;
  int rc;
  int error = 0;
  bool isconnected = FALSE;
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd;
  CURLcode res = CURLE_OK;
#if defined(ENABLE_IPV6) && defined(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  struct sockaddr_in6 * const sa6 = (void *)&addr.sa_addr;
#endif

  *sockp = CURL_SOCKET_BAD;

  /*
   * The Curl_sockaddr_ex structure is basically libcurl's external API
   * curl_sockaddr structure with enough space available to directly hold
   * any protocol-specific address structures. The variable declared here
   * will be used to pass / receive data to/from the fopensocket callback
   * if this has been set, before that, it is initialized from parameters.
   */

  addr.family = ai->ai_family;
  addr.socktype = conn->socktype;
  addr.protocol = conn->socktype==SOCK_DGRAM?IPPROTO_UDP:ai->ai_protocol;
  addr.addrlen = ai->ai_addrlen;

  if(addr.addrlen > sizeof(struct Curl_sockaddr_storage))
     addr.addrlen = sizeof(struct Curl_sockaddr_storage);
  memcpy(&addr.sa_addr, ai->ai_addr, addr.addrlen);

  *connected = FALSE; /* default is not connected */

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
    sockfd = data->set.fopensocket(data->set.opensocket_client,
                                   CURLSOCKTYPE_IPCXN,
                                   (struct curl_sockaddr *)&addr);
  else
    /* opensocket callback not set, so simply create the socket now */
    sockfd = socket(addr.family, addr.socktype, addr.protocol);

  if(sockfd == CURL_SOCKET_BAD)
    /* no socket, no connection */
    return CURLE_OK;

#if defined(ENABLE_IPV6) && defined(HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID)
  if(conn->scope && (addr.family == AF_INET6))
    sa6->sin6_scope_id = conn->scope;
#endif

  /* store remote address and port used in this connection attempt */
  if(!getaddressinfo((struct sockaddr*)&addr.sa_addr,
                     conn->primary_ip, &conn->primary_port)) {
    /* malformed address or bug in inet_ntop, try next address */
    error = ERRNO;
    failf(data, "sa_addr inet_ntop() failed with errno %d: %s",
          error, Curl_strerror(conn, error));
    Curl_closesocket(conn, sockfd);
    return CURLE_OK;
  }
  memcpy(conn->ip_addr_str, conn->primary_ip, MAX_IPADR_LEN);
  infof(data, "  Trying %s... ", conn->ip_addr_str);

  Curl_persistconninfo(conn);

  if(data->set.tcp_nodelay)
    tcpnodelay(conn, sockfd);

  nosigpipe(conn, sockfd);

  Curl_sndbufset(sockfd);

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
  res = bindlocal(conn, sockfd, addr.family);
  if(res) {
    Curl_closesocket(conn, sockfd); /* close socket and bail out */
    return res;
  }

  /* set socket non-blocking */
  curlx_nonblock(sockfd, TRUE);

  /* Connect TCP sockets, bind UDP */
  if(!isconnected && (conn->socktype == SOCK_STREAM)) {
    rc = connect(sockfd, &addr.sa_addr, addr.addrlen);
    if(-1 == rc)
      error = SOCKERRNO;
    conn->connecttime = Curl_tvnow();
    if(conn->num_addr > 1)
      Curl_expire(data, conn->timeoutms_per_addr);
  }
  else
    rc = 0;

  if(-1 == rc) {
    switch (error) {
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
      rc = waitconnect(conn, sockfd, timeout_ms);
      if(WAITCONN_ABORTED == rc) {
        Curl_closesocket(conn, sockfd);
        return CURLE_ABORTED_BY_CALLBACK;
      }
      break;
    default:
      /* unknown error, fallthrough and try another address! */
      failf(data, "Failed to connect to %s: %s",
            conn->ip_addr_str, Curl_strerror(conn,error));
      data->state.os_errno = error;
      break;
    }
  }

  /* The 'WAITCONN_TIMEOUT == rc' comes from the waitconnect(), and not from
     connect(). We can be sure of this since connect() cannot return 1. */
  if((WAITCONN_TIMEOUT == rc) &&
     (data->state.used_interface == Curl_if_multi)) {
    /* Timeout when running the multi interface */
    *sockp = sockfd;
    return CURLE_OK;
  }

  if(!isconnected)
    isconnected = verifyconnect(sockfd, &error);

  if(!rc && isconnected) {
    /* we are connected, awesome! */
    *connected = TRUE; /* this is a true connect */
    infof(data, "connected\n");
#ifdef ENABLE_IPV6
    conn->bits.ipv6 = (addr.family == AF_INET6)?TRUE:FALSE;
#endif

    Curl_updateconninfo(conn, sockfd);
    *sockp = sockfd;
    return CURLE_OK;
  }
  else if(WAITCONN_TIMEOUT == rc)
    infof(data, "Timeout\n");
  else {
    data->state.os_errno = error;
    infof(data, "%s\n", Curl_strerror(conn, error));
  }

  /* connect failed or timed out */
  Curl_closesocket(conn, sockfd);

  return CURLE_OK;
}

/*
 * TCP connect to the given host with timeout, proxy or remote doesn't matter.
 * There might be more than one IP address to try out. Fill in the passed
 * pointer with the connected socket.
 */

CURLcode Curl_connecthost(struct connectdata *conn,  /* context */
                          const struct Curl_dns_entry *remotehost,
                          curl_socket_t *sockconn,   /* the connected socket */
                          Curl_addrinfo **addr,      /* the one we used */
                          bool *connected)           /* really connected? */
{
  struct SessionHandle *data = conn->data;
  curl_socket_t sockfd = CURL_SOCKET_BAD;
  int aliasindex;
  Curl_addrinfo *ai;
  Curl_addrinfo *curr_addr;

  struct timeval after;
  struct timeval before = Curl_tvnow();

  /*************************************************************
   * Figure out what maximum time we have left
   *************************************************************/
  long timeout_ms;

  DEBUGASSERT(sockconn);
  *connected = FALSE; /* default to not connected */

  /* get the timeout left */
  timeout_ms = Curl_timeleft(data, &before, TRUE);

  if(timeout_ms < 0) {
    /* a precaution, no need to continue if time already is up */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  /* Max time for each address */
  conn->num_addr = Curl_num_addresses(remotehost->addr);
  conn->timeoutms_per_addr = timeout_ms / conn->num_addr;

  ai = remotehost->addr;

  /* Below is the loop that attempts to connect to all IP-addresses we
   * know for the given host. One by one until one IP succeeds.
   */

  /*
   * Connecting with a Curl_addrinfo chain
   */
  for(curr_addr = ai, aliasindex=0; curr_addr;
      curr_addr = curr_addr->ai_next, aliasindex++) {

    /* start connecting to the IP curr_addr points to */
    CURLcode res =
      singleipconnect(conn, curr_addr,
                      /* don't hang when doing multi */
                      (data->state.used_interface == Curl_if_multi)?0:
                      conn->timeoutms_per_addr, &sockfd, connected);

    if(res)
      return res;

    if(sockfd != CURL_SOCKET_BAD)
      break;

    /* get a new timeout for next attempt */
    after = Curl_tvnow();
    timeout_ms -= Curl_tvdiff(after, before);
    if(timeout_ms < 0) {
      failf(data, "connect() timed out!");
      return CURLE_OPERATION_TIMEDOUT;
    }
    before = after;
  }  /* end of connect-to-each-address loop */

  *sockconn = sockfd;    /* the socket descriptor we've connected */

  if(sockfd == CURL_SOCKET_BAD) {
    /* no good connect was made */
    failf(data, "couldn't connect to host");
    return CURLE_COULDNT_CONNECT;
  }

  /* leave the socket in non-blocking mode */

  /* store the address we use */
  if(addr)
    *addr = curr_addr;

  data->info.numconnects++; /* to track the number of connections made */

  return CURLE_OK;
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

  if((data->state.lastconnect != -1) &&
     (data->state.connc->connects[data->state.lastconnect] != NULL)) {
    struct connectdata *c =
      data->state.connc->connects[data->state.lastconnect];
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
  if(conn && conn->fclosesocket)
    return conn->fclosesocket(conn->closesocket_client, sock);
  else
    return sclose(sock);
}
