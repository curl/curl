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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

typedef struct prcs
{
  int prereq_retcode;
  int ipv6;
} PRCS;

static int prereq_callback(void *clientp,
                           char *conn_primary_ip,
                           char *conn_local_ip,
                           int conn_primary_port,
                           int conn_local_port)
{
  PRCS *prereq_cb = (PRCS *)clientp;

  if (prereq_cb->ipv6)
  {
    printf("Connected to [%s]\n", conn_primary_ip);
    printf("Connected from [%s]\n", conn_local_ip);
  }
  else
  {
    printf("Connected to %s\n", conn_primary_ip);
    printf("Connected from %s\n", conn_local_ip);
  }

  printf("Remote port = %d\n", conn_primary_port);
  printf("Local port = %d\n", conn_local_port);
  printf("Returning = %d\n", prereq_cb->prereq_retcode);
  return prereq_cb->prereq_retcode;
}

FETCHcode test(char *URL)
{
  PRCS prereq_cb;
  FETCHcode ret = FETCHE_OK;
  FETCH *fetch = NULL;

  prereq_cb.prereq_retcode = FETCH_PREREQFUNC_OK;
  prereq_cb.ipv6 = 0;

  fetch_global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();

  if (fetch)
  {
    if (strstr(URL, "#ipv6"))
    {
      /* The IP addresses should be surrounded by brackets! */
      prereq_cb.ipv6 = 1;
    }
    if (strstr(URL, "#err"))
    {
      /* Set the callback to exit with failure */
      prereq_cb.prereq_retcode = FETCH_PREREQFUNC_ABORT;
    }

    fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
    fetch_easy_setopt(fetch, FETCHOPT_PREREQFUNCTION, prereq_callback);
    fetch_easy_setopt(fetch, FETCHOPT_PREREQDATA, &prereq_cb);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, stderr);

    if (strstr(URL, "#redir"))
    {
      /* Enable follow-location */
      fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1);
    }

    ret = fetch_easy_perform(fetch);
    if (ret)
    {
      fprintf(stderr, "%s:%d fetch_easy_perform() failed with code %d (%s)\n",
              __FILE__, __LINE__, ret, fetch_easy_strerror(ret));
      goto test_cleanup;
    }
  }

test_cleanup:
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return ret;
}
