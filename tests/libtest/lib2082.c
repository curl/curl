/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Max Dymond, <max.dymond@microsoft.com>
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
#include "first.h"

struct prcs {
  int prereq_retcode;
  int ipv6;
};

static int prereq_callback(void *clientp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
  struct prcs *prereq_cb = (struct prcs *)clientp;

  if(prereq_cb->ipv6) {
    curl_mprintf("Connected to [%s]\n", conn_primary_ip);
    curl_mprintf("Connected from [%s]\n", conn_local_ip);
  }
  else {
    curl_mprintf("Connected to %s\n", conn_primary_ip);
    curl_mprintf("Connected from %s\n", conn_local_ip);
  }

  curl_mprintf("Remote port = %d\n", conn_primary_port);
  curl_mprintf("Local port = %d\n", conn_local_port);
  curl_mprintf("Returning = %d\n", prereq_cb->prereq_retcode);
  return prereq_cb->prereq_retcode;
}

static CURLcode test_lib2082(const char *URL)  /* libprereq */
{
  struct prcs prereq_cb;
  CURLcode ret = CURLE_OK;
  CURL *curl = NULL;

  prereq_cb.prereq_retcode = CURL_PREREQFUNC_OK;
  prereq_cb.ipv6 = 0;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  if(curl) {
    if(strstr(URL, "#ipv6")) {
      /* The IP addresses should be surrounded by brackets! */
      prereq_cb.ipv6 = 1;
    }
    if(strstr(URL, "#err")) {
      /* Set the callback to exit with failure */
      prereq_cb.prereq_retcode = CURL_PREREQFUNC_ABORT;
    }

    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, prereq_callback);
    curl_easy_setopt(curl, CURLOPT_PREREQDATA, &prereq_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, stderr);

    if(strstr(URL, "#redir")) {
      /* Enable follow-location */
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    }

    ret = curl_easy_perform(curl);
    if(ret) {
      curl_mfprintf(stderr,
                    "%s:%d curl_easy_perform() failed with code %d (%s)\n",
                    __FILE__, __LINE__, ret, curl_easy_strerror(ret));
      goto test_cleanup;
    }
  }

test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return ret;
}
