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
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <errno.h>

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
#endif

#include "urldata.h"
#include "sendf.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/*************************************************************************
 * Curl_nonblock
 *
 * Description:
 *  Set the socket to either blocking or non-blocking mode.
 */
static
int nonblock(int socket,    /* operate on this */
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
  struct timeval interval;
  int rc;

  /* now select() until we get connect or timeout */
  FD_ZERO(&fd);
  FD_SET(sockfd, &fd);

  interval.tv_sec = timeout_msec/1000;
  timeout_msec -= interval.tv_sec*1000;

  interval.tv_usec = timeout_msec*1000;

  rc = select(sockfd+1, NULL, &fd, NULL, &interval);
  if(-1 == rc)
    /* error, no connect here, try next */
    return -1;
  
  else if(0 == rc)
    /* timeout, no connect today */
    return 1;

  /* we have a connect! */
  return 0;
}

/*
 * TCP connect to the given host with timeout, proxy or remote doesn't matter.
 * There might be more than one IP address to try out. Fill in the passed
 * pointer with the connected socket.
 */

CURLcode Curl_connecthost(struct connectdata *conn,
                          int sockfd, /* input socket, or -1 if none */
                          int *socket)
{
  struct SessionHandle *data = conn->data;
  int rc;

#ifdef ENABLE_IPV6
  /*
   * Connecting with IPv6 support is so much easier and cleanly done
   */
  if(sockfd != -1)
    /* don't use any previous one, it might be of wrong type */
    sclose(sockfd);
  sockfd = -1; /* none! */
  for (ai = conn->hp; ai; ai = ai->ai_next) {
    sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sockfd < 0)
      continue;

    /* set socket non-blocking */
    nonblock(sockfd, TRUE);

    rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);

    if(0 == rc)
      /* direct connect, awesome! */
      break;

    /* asynchronous connect, wait for connect or timeout */
    rc = waitconnect(sockfd, timeout);
    if(0 != rc) {
      /* connect failed or timed out */
      sclose(sockfd);
      sockfd = -1;
      continue;
    }

    /* now disable the non-blocking mode again */
    nonblock(sockfd, FALSE);
    break;
  }
  conn->ai = ai;
  if (sockfd < 0) {
    failf(data, strerror(errno));
    return CURLE_COULDNT_CONNECT;
  }
#else
  /*
   * Connecting with IPv4-only support
   */
  int aliasindex;
  int timeout_ms = 10000; /* while testing */

  /* non-block socket */
  nonblock(sockfd, TRUE);

  /* This is the loop that attempts to connect to all IP-addresses we
     know for the given host. One by one. */
  for(rc=-1, aliasindex=0;
      rc && (struct in_addr *)conn->hp->h_addr_list[aliasindex];
      aliasindex++) {

    /* copy this particular name info to the conn struct as it might
       be used later in the krb4 "system" */
    memset((char *) &conn->serv_addr, '\0', sizeof(conn->serv_addr));
    memcpy((char *)&(conn->serv_addr.sin_addr),
           (struct in_addr *)conn->hp->h_addr_list[aliasindex],
           sizeof(struct in_addr));
    conn->serv_addr.sin_family = conn->hp->h_addrtype;
    conn->serv_addr.sin_port = htons(conn->port);
  
    rc = connect(sockfd, (struct sockaddr *)&(conn->serv_addr),
                 sizeof(conn->serv_addr));

    if(-1 == rc) {
      int error;
#ifdef WIN32
      error = (int)GetLastError();
#else
      error = errno;
#endif
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
        break;
      }
    }

    if(0 != rc)
      continue; /* try next address */
    else
      break;
  }
  if(-1 == rc) {
    /* no good connect was made */
    sclose(sockfd);
    *socket = -1;
    failf(data, "Couldn't connect to (any) IP address");
    return CURLE_COULDNT_CONNECT;
  }
  
  /* now disable the non-blocking mode again */
  nonblock(sockfd, FALSE);

#endif

  *socket = sockfd; /* pass this to our parent */

  return CURLE_OK;
}

