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

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#endif

#include "nonblock.h"

/*
 * curlx_nonblock() set the given socket to either blocking or non-blocking
 * mode based on the 'nonblock' boolean argument. This function is highly
 * portable.
 */
int curlx_nonblock(curl_socket_t sockfd,    /* operate on this */
                   int nonblock   /* TRUE or FALSE */)
{
#if defined(HAVE_FCNTL_O_NONBLOCK)
  /* most recent Unix versions */
  int flags;
  flags = sfcntl(sockfd, F_GETFL, 0);
  if(flags < 0)
    return -1;
  /* Check if the current file status flags have already satisfied
   * the request, if so, it is no need to call fcntl() to replicate it.
   */
  if(!!(flags & O_NONBLOCK) == !!nonblock)
    return 0;
  if(nonblock)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  return sfcntl(sockfd, F_SETFL, flags);

#elif defined(HAVE_IOCTLSOCKET_CAMEL_FIONBIO)

  /* Amiga */
  long flags = nonblock ? 1L : 0L;
  return IoctlSocket(sockfd, FIONBIO, (char *)&flags);

#elif defined(HAVE_IOCTL_FIONBIO)

  /* older Unix versions */
  int flags = nonblock ? 1 : 0;
  return ioctl(sockfd, FIONBIO, &flags);

#elif defined(HAVE_IOCTLSOCKET_FIONBIO)

  /* Windows */
  unsigned long flags = nonblock ? 1UL : 0UL;
  return ioctlsocket(sockfd, (long)FIONBIO, &flags);

#elif defined(HAVE_SETSOCKOPT_SO_NONBLOCK)

  /* Orbis OS */
  long b = nonblock ? 1L : 0L;
  return setsockopt(sockfd, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));

#else
#  error "no non-blocking method was found/used/set"
#endif
}
