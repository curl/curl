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

#include <curl/curl.h>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_cb_rea.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_READFUNCTION
*/

size_t tool_read_cb(void *buffer, size_t sz, size_t nmemb, void *userdata)
{
  ssize_t rc;
  struct InStruct *in = userdata;

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
  return (size_t)rc;
}

