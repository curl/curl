/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"

#ifndef WIN32
/* headers for non-win32 */
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifdef WIN32
#define HAVE_IOCTLSOCKET
#include <windows.h>
#include <winsock.h>
#define EINPROGRESS WSAEINPROGRESS
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EISCONN     WSAEISCONN
#endif

#include "urldata.h"
#include "sendf.h"
#include "if2ip.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

static
int geterrno(void)
{
#ifdef WIN32
  return (int)GetLastError();
#else
  return errno;
#endif
}

/*************************************************************************
 * Curl_nonblock
 *
 * Description:
 *  Set the socket to either blocking or non-blocking mode.
 */

int Curl_nonblock(int socket,    /* operate on this */
                  int nonblock   /* TRUE or FALSE */)
{
#undef SETBLOCK
#ifdef HAVE_O_NONBLOCK
  int flags;

  flags = fcntl(socket, F_GETFL, 0);
  if (TRUE == nonblock)
    return fcntl(socket, F_SETFL, flags | O_NONBLOCK);
  else
    return fcntl(socket, F_SETFL, flags & (~O_NONBLOCK));
#define SETBLOCK 1
#endif

#ifdef HAVE_FIONBIO
  int flags;

  flags = nonblock;
  return ioctl(socket, FIONBIO, &flags);
#define SETBLOCK 2
#endif

#ifdef HAVE_IOCTLSOCKET
  int flags;
  flags = nonblock;
  return ioctlsocket(socket, FIONBIO, &flags);
#define SETBLOCK 3
#endif

#ifdef HAVE_IOCTLSOCKET_CASE
  return IoctlSocket(socket, FIONBIO, (long)nonblock);
#define SETBLOCK 4
#endif

#ifdef HAVE_DISABLED_NONBLOCKING
  return 0; /* returns success */
#define SETBLOCK 5
#endif

#ifndef SETBLOCK
#error "no non-blocking method was found/used/set"
#endif
}

/*
 * Return 0 on fine connect, -1 on error and 1 on timeout.
 */
static
int waitconnect(int sockfd, /* socket */
                int timeout_msec)
{
  fd_set fd;
  fd_set errfd;
  struct timeval interval;
  int rc;

  /* now select() until we get connect or timeout */
  FD_ZERO(&fd);
  FD_SET(sockfd, &fd);

  FD_ZERO(&errfd);
  FD_SET(sockfd, &errfd);

  interval.tv_sec = timeout_msec/1000;
  timeout_msec -= interval.tv_sec*1000;

  interval.tv_usec = timeout_msec*1000;

  rc = select(sockfd+1, NULL, &fd, &errfd, &interval);
  if(-1 == rc)
    /* error, no connect here, try next */
    return -1;
  
  else if(0 == rc)
    /* timeout, no connect today */
    return 1;

  if(FD_ISSET(sockfd, &errfd)) {
    /* error condition caught */
    return 2;
  }

  /* we have a connect! */
  return 0;
}

#ifndef ENABLE_IPV6
static CURLcode bindlocal(struct connectdata *conn,
                          int sockfd)
{
#if !defined(WIN32)||defined(__CYGWIN32__)
  /* We don't generally like checking for OS-versions, we should make this
     HAVE_XXXX based, although at the moment I don't have a decent test for
     this! */

#ifdef HAVE_INET_NTOA

#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif

  struct SessionHandle *data = conn->data;

  /*************************************************************
   * Select device to bind socket to
   *************************************************************/
  if (strlen(data->set.device)<255) {
    struct sockaddr_in sa;
    struct hostent *h=NULL;
    char *hostdataptr=NULL;
    size_t size;
    char myhost[256] = "";
    unsigned long in;

    if(Curl_if2ip(data->set.device, myhost, sizeof(myhost))) {
      h = Curl_getaddrinfo(data, myhost, 0, &hostdataptr);
    }
    else {
      if(strlen(data->set.device)>1) {
        h = Curl_getaddrinfo(data, data->set.device, 0, &hostdataptr);
      }
      if(h) {
        /* we know data->set.device is shorter than the myhost array */
        strcpy(myhost, data->set.device);
      }
    }

    if(! *myhost) {
      /* need to fix this
         h=Curl_gethost(data,
         getmyhost(*myhost,sizeof(myhost)),
         hostent_buf,
         sizeof(hostent_buf));
      */
      if(hostdataptr)
        free(hostdataptr); /* allocated by Curl_getaddrinfo() */
      return CURLE_HTTP_PORT_FAILED;
    }

    infof(data, "We bind local end to %s\n", myhost);

    if ( (in=inet_addr(myhost)) != INADDR_NONE ) {

      if ( h ) {
        memset((char *)&sa, 0, sizeof(sa));
        memcpy((char *)&sa.sin_addr,
               h->h_addr,
               h->h_length);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = in;
        sa.sin_port = 0; /* get any port */
	
        if( bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) >= 0) {
          /* we succeeded to bind */
          struct sockaddr_in add;
	
          size = sizeof(add);
          if(getsockname(sockfd, (struct sockaddr *) &add,
                         (socklen_t *)&size)<0) {
            failf(data, "getsockname() failed");
            return CURLE_HTTP_PORT_FAILED;
          }
        }
        else {
          switch(errno) {
          case EBADF:
            failf(data, "Invalid descriptor: %d", errno);
            break;
          case EINVAL:
            failf(data, "Invalid request: %d", errno);
            break;
          case EACCES:
            failf(data, "Address is protected, user not superuser: %d", errno);
            break;
          case ENOTSOCK:
            failf(data,
                  "Argument is a descriptor for a file, not a socket: %d",
                  errno);
            break;
          case EFAULT:
            failf(data, "Inaccessable memory error: %d", errno);
            break;
          case ENAMETOOLONG:
            failf(data, "Address too long: %d", errno);
            break;
          case ENOMEM:
            failf(data, "Insufficient kernel memory was available: %d", errno);
            break;
          default:
            failf(data, "errno %d\n", errno);
            break;
          } /* end of switch(errno) */
	
          return CURLE_HTTP_PORT_FAILED;
        } /* end of else */
	
      } /* end of if  h */
      else {
	failf(data,"could't find my own IP address (%s)", myhost);
	return CURLE_HTTP_PORT_FAILED;
      }
    } /* end of inet_addr */

    else {
      failf(data, "could't find my own IP address (%s)", myhost);
      return CURLE_HTTP_PORT_FAILED;
    }

    if(hostdataptr)
      free(hostdataptr); /* allocated by Curl_getaddrinfo() */

    return CURLE_OK;

  } /* end of device selection support */
#endif /* end of HAVE_INET_NTOA */
#endif /* end of not WIN32 */

  return CURLE_HTTP_PORT_FAILED;
}
#endif /* end of ipv4-specific section */

static
int socketerror(int sockfd)
{
  int err = 0;
  socklen_t errSize = sizeof(err);

  if( -1 == getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
                       (void *)&err, &errSize))
    err = geterrno();
  
  return err;
}

/*
 * TCP connect to the given host with timeout, proxy or remote doesn't matter.
 * There might be more than one IP address to try out. Fill in the passed
 * pointer with the connected socket.
 */

CURLcode Curl_connecthost(struct connectdata *conn,  /* context */
                          Curl_addrinfo *remotehost, /* use one in here */
                          int port,                  /* connect to this */
                          int *sockconn,             /* the connected socket */
                          Curl_ipconnect **addr)     /* the one we used */
{
  struct SessionHandle *data = conn->data;
  int rc;
  int sockfd=-1;
  int aliasindex=0;

  struct timeval after;
  struct timeval before = Curl_tvnow();

  /*************************************************************
   * Figure out what maximum time we have left
   *************************************************************/
  long timeout_ms=300000; /* milliseconds, default to five minutes */
  if(data->set.timeout || data->set.connecttimeout) {
    double has_passed;

    /* Evaluate in milliseconds how much time that has passed */
    has_passed = Curl_tvdiff(Curl_tvnow(), data->progress.start);

#ifndef min
#define min(a, b)   ((a) < (b) ? (a) : (b))
#endif

    /* get the most strict timeout of the ones converted to milliseconds */
    if(data->set.timeout &&
       (data->set.timeout>data->set.connecttimeout))
      timeout_ms = data->set.timeout*1000;
    else
      timeout_ms = data->set.connecttimeout*1000;

    /* subtract the passed time */
    timeout_ms -= (long)has_passed;

    if(timeout_ms < 0)
      /* a precaution, no need to continue if time already is up */
      return CURLE_OPERATION_TIMEOUTED;
  }

#ifdef ENABLE_IPV6
  /*
   * Connecting with IPv6 support is so much easier and cleanly done
   */
  {
    struct addrinfo *ai;
    port =0; /* prevent compiler warning */

    for (ai = remotehost; ai; ai = ai->ai_next, aliasindex++) {
      sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (sockfd < 0)
        continue;

      /* set socket non-blocking */
      Curl_nonblock(sockfd, TRUE);

      rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);

      if(-1 == rc) {
        int error=geterrno();

        switch (error) {
        case EINPROGRESS:
        case EWOULDBLOCK:
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
          /* On some platforms EAGAIN and EWOULDBLOCK are the
           * same value, and on others they are different, hence
           * the odd #if
           */
        case EAGAIN:
#endif
        case EINTR:

          /* asynchronous connect, wait for connect or timeout */
          rc = waitconnect(sockfd, timeout_ms);
          break;
        case ECONNREFUSED: /* no one listening */
        default:
          /* unknown error, fallthrough and try another address! */
          failf(data, "Failed to connect");
          break;
        }
      }
      if(0 == rc) {
        /* we might be connected, if the socket says it is OK! Ask it! */
        int err;

        err = socketerror(sockfd);
        if ((0 == err) || (EISCONN == err)) {
          /* we are connected, awesome! */
          break;
	}
        /* we are _not_ connected, it was a false alert, continue please */
      }

      /* connect failed or timed out */
      sclose(sockfd);
      sockfd = -1;

      /* get a new timeout for next attempt */
      after = Curl_tvnow();
      timeout_ms -= Curl_tvdiff(after, before);
      if(timeout_ms < 0) {
        failf(data, "connect() timed out!");
        return CURLE_OPERATION_TIMEOUTED;
      }
      before = after;
      continue;
    }
    if (sockfd < 0) {
      failf(data, "connect() failed");
      return CURLE_COULDNT_CONNECT;
    }

    /* now disable the non-blocking mode again */
    Curl_nonblock(sockfd, FALSE);

    if(addr)
      *addr = ai; /* the address we ended up connected to */
  }
#else
  /*
   * Connecting with IPv4-only support
   */
  if(!remotehost->h_addr_list[0]) {
    /* If there is no addresses in the address list, then we return
       error right away */
    failf(data, "no address available");
    return CURLE_COULDNT_CONNECT;
  }
  /* create an IPv4 TCP socket */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(-1 == sockfd) {
    failf(data, "couldn't create socket");
    return CURLE_COULDNT_CONNECT; /* big time error */
  }
  
  if(conn->data->set.device) {
    /* user selected to bind the outgoing socket to a specified "device"
       before doing connect */
    CURLcode res = bindlocal(conn, sockfd);
    if(res)
      return res;
  }

  /* Convert socket to non-blocking type */
  Curl_nonblock(sockfd, TRUE);

  /* This is the loop that attempts to connect to all IP-addresses we
     know for the given host. One by one. */
  for(rc=-1, aliasindex=0;
      rc && (struct in_addr *)remotehost->h_addr_list[aliasindex];
      aliasindex++) {
    struct sockaddr_in serv_addr;

    /* do this nasty work to do the connect */
    memset((char *) &serv_addr, '\0', sizeof(serv_addr));
    memcpy((char *)&(serv_addr.sin_addr),
           (struct in_addr *)remotehost->h_addr_list[aliasindex],
           sizeof(struct in_addr));
    serv_addr.sin_family = remotehost->h_addrtype;
    serv_addr.sin_port = htons(port);
  
    rc = connect(sockfd, (struct sockaddr *)&serv_addr,
                 sizeof(serv_addr));

    if(-1 == rc) {
      int error=geterrno();

      switch (error) {
      case EINPROGRESS:
      case EWOULDBLOCK:
#if defined(EAGAIN) && EAGAIN != EWOULDBLOCK
        /* On some platforms EAGAIN and EWOULDBLOCK are the
         * same value, and on others they are different, hence
         * the odd #if
         */
      case EAGAIN:
#endif

        /* asynchronous connect, wait for connect or timeout */
        rc = waitconnect(sockfd, timeout_ms);
        break;
      default:
        /* unknown error, fallthrough and try another address! */
        failf(data, "Failed to connect to IP number %d", aliasindex+1);
        break;
      }
    }

    if(0 == rc) {
      int err = socketerror(sockfd);
      if ((0 == err) || (EISCONN == err)) {
        /* we are connected, awesome! */
        break;
      }
      /* nope, not connected for real */
      rc = -1;
    }

    if(0 != rc) {
      /* get a new timeout for next attempt */
      after = Curl_tvnow();
      timeout_ms -= Curl_tvdiff(after, before);
      if(timeout_ms < 0) {
        failf(data, "Connect timeout on IP number %d", aliasindex+1);
        break;
      }
      before = after;
      continue; /* try next address */
    }
    break;
  }
  if(0 != rc) {
    /* no good connect was made */
    sclose(sockfd);
    *sockconn = -1;
    failf(data, "Couldn't connect to host");
    return CURLE_COULDNT_CONNECT;
  }
  
  /* now disable the non-blocking mode again */
  Curl_nonblock(sockfd, FALSE);

  if(addr)
    /* this is the address we've connected to */
    *addr = (struct in_addr *)remotehost->h_addr_list[aliasindex];
#endif

  /* allow NULL-pointers to get passed in */
  if(sockconn)
    *sockconn = sockfd;    /* the socket descriptor we've connected */

  return CURLE_OK;
}

