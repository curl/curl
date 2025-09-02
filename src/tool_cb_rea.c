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
#include "tool_setup.h"

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "tool_cfgable.h"
#include "tool_cb_rea.h"
#include "tool_operate.h"
#include "tool_util.h"
#include "tool_msgs.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_READFUNCTION
*/

size_t tool_read_cb(char *buffer, size_t sz, size_t nmemb, void *userdata)
{
  ssize_t rc = 0;
  struct per_transfer *per = userdata;
  struct OperationConfig *config = per->config;

  if((per->uploadfilesize != -1) &&
     (per->uploadedsofar == per->uploadfilesize)) {
    /* done */
    return 0;
  }

  if(config->timeout_ms) {
    struct curltime now = curlx_now();
    long msdelta = (long)curlx_timediff(now, per->start);

    if(msdelta > config->timeout_ms)
      /* timeout */
      return 0;
#ifndef _WIN32
    /* this logic waits on read activity on a file descriptor that is not a
       socket which makes it not work with select() on Windows */
    else {
      fd_set bits;
      struct timeval timeout;
      long wait = config->timeout_ms - msdelta;

      /* wait this long at the most */
      timeout.tv_sec = wait/1000;
      timeout.tv_usec = (int)((wait%1000)*1000);

      FD_ZERO(&bits);
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
      FD_SET(per->infd, &bits);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
      if(!select(per->infd + 1, &bits, NULL, NULL, &timeout))
        return 0; /* timeout */
    }
#endif
  }

  /* If we are on Windows, and using `-T .`, then per->infd points to a socket
   connected to stdin via a reader thread, and needs to be read with recv()
   Make sure we are in non-blocking mode and infd is not regular stdin
   On Linux per->infd should be stdin (0) and the block below should not
   execute */
  if(per->uploadfile && !strcmp(per->uploadfile, ".") && per->infd > 0) {
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
    rc = recv(per->infd, buffer, curlx_uztosi(sz * nmemb), 0);
    if(rc < 0) {
      if(SOCKERRNO == SOCKEWOULDBLOCK) {
        CURL_SETERRNO(0);
        config->readbusy = TRUE;
        return CURL_READFUNC_PAUSE;
      }

      rc = 0;
    }
#else
    warnf("per->infd != 0: FD == %d. This behavior"
          " is only supported on desktop Windows", per->infd);
#endif
  }
  else {
    rc = read(per->infd, buffer, sz*nmemb);
    if(rc < 0) {
      if(errno == EAGAIN) {
        CURL_SETERRNO(0);
        config->readbusy = TRUE;
        return CURL_READFUNC_PAUSE;
      }
      /* since size_t is unsigned we cannot return negative values fine */
      rc = 0;
    }
  }
  if((per->uploadfilesize != -1) &&
     (per->uploadedsofar + rc > per->uploadfilesize)) {
    /* do not allow uploading more than originally set out to do */
    curl_off_t delta = per->uploadedsofar + rc - per->uploadfilesize;
    warnf("File size larger in the end than when "
          "started. Dropping at least %" CURL_FORMAT_CURL_OFF_T " bytes",
          delta);
    rc = (ssize_t)(per->uploadfilesize - per->uploadedsofar);
  }
  config->readbusy = FALSE;

  /* when select() returned zero here, it timed out */
  return (size_t)rc;
}

/*
** callback for CURLOPT_XFERINFOFUNCTION used to unpause busy reads
*/

int tool_readbusy_cb(void *clientp,
                     curl_off_t dltotal, curl_off_t dlnow,
                     curl_off_t ultotal, curl_off_t ulnow)
{
  struct per_transfer *per = clientp;
  struct OperationConfig *config = per->config;
  static curl_off_t ulprev;

  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;

  if(config->readbusy) {
    if(ulprev == ulnow) {
#ifndef _WIN32
      fd_set bits;
      struct timeval timeout;
      /* wait this long at the most */
      timeout.tv_sec = 0;
      timeout.tv_usec = 1000;

      FD_ZERO(&bits);
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
      FD_SET(per->infd, &bits);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
      select(per->infd + 1, &bits, NULL, NULL, &timeout);
#else
      /* sleep */
      curlx_wait_ms(1);
#endif
    }

    config->readbusy = FALSE;
    curl_easy_pause(per->curl, CURLPAUSE_CONT);
  }

  ulprev = ulnow;

  return per->noprogress ? 0 : CURL_PROGRESSFUNC_CONTINUE;
}
