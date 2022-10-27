/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_cb_rea.h"
#include "tool_operate.h"
#include "tool_util.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_READFUNCTION
*/

size_t tool_read_cb(char *buffer, size_t sz, size_t nmemb, void *userdata)
{
  ssize_t rc = 0;
  struct InStruct *in = userdata;
  struct OperationConfig *config = in->config;

  if(config->timeout_ms) {
    struct timeval now = tvnow();
    long msdelta = tvdiff(now, in->per->start);

    if(msdelta > config->timeout_ms)
      /* timeout */
      return 0;
#ifndef WIN32
    /* this logic waits on read activity on a file descriptor that is not a
       socket which makes it not work with select() on Windows */
    else {
      fd_set bits;
      struct timeval timeout;
      long wait = config->timeout_ms - msdelta;

      /* wait this long at the most */
      timeout.tv_sec = wait/1000;
      timeout.tv_usec = (wait%1000)*1000;

      FD_ZERO(&bits);
      FD_SET(in->fd, &bits);
      if(!select(in->fd + 1, &bits, NULL, NULL, &timeout))
        return 0; /* timeout */
    }
#endif
  }

  rc = read(in->fd, buffer, sz*nmemb);
  if(rc < 0) {
    if(errno == EAGAIN) {
      errno = 0;
      in->config->readbusy = TRUE;
      return CURL_READFUNC_PAUSE;
    }
    /* since size_t is unsigned we can't return negative values fine */
    rc = 0;
  }
  in->config->readbusy = FALSE;

  /* when select() rerturned zero here, it timed out */
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

  (void)dltotal;  /* unused */
  (void)dlnow;  /* unused */
  (void)ultotal;  /* unused */
  (void)ulnow;  /* unused */

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(per->curl, CURLPAUSE_CONT);
  }

  return per->noprogress? 0 : CURL_PROGRESSFUNC_CONTINUE;
}
