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
 * are also available at https://fetch.se/docs/copyright.html.
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

/*
  Check range/resume returned error codes and data presence.

  The input parameters are:
  - FETCHOPT_RANGE/FETCHOPT_RESUME_FROM
  - FETCHOPT_FAILONERROR
  - Returned http code (2xx/416)
  - Content-Range header present in reply.

*/

#include "memdebug.h"

#define F_RESUME (1 << 0)       /* resume/range. */
#define F_HTTP416 (1 << 1)      /* Server returns http code 416. */
#define F_FAIL (1 << 2)         /* Fail on error. */
#define F_CONTENTRANGE (1 << 3) /* Server sends content-range hdr. */
#define F_IGNOREBODY (1 << 4)   /* Body should be ignored. */

struct testparams
{
  unsigned int flags; /* ORed flags as above. */
  FETCHcode result;   /* Code that should be returned by fetch_easy_perform(). */
};

static const struct testparams testparams[] = {
    {0, FETCHE_OK},
    {F_CONTENTRANGE, FETCHE_OK},
    {F_FAIL, FETCHE_OK},
    {F_FAIL | F_CONTENTRANGE, FETCHE_OK},
    {F_HTTP416, FETCHE_OK},
    {F_HTTP416 | F_CONTENTRANGE, FETCHE_OK},
    {F_HTTP416 | F_FAIL | F_IGNOREBODY,
     FETCHE_HTTP_RETURNED_ERROR},
    {F_HTTP416 | F_FAIL | F_CONTENTRANGE | F_IGNOREBODY,
     FETCHE_HTTP_RETURNED_ERROR},
    {F_RESUME | F_IGNOREBODY,
     FETCHE_RANGE_ERROR},
    {F_RESUME | F_CONTENTRANGE, FETCHE_OK},
    {F_RESUME | F_FAIL | F_IGNOREBODY,
     FETCHE_RANGE_ERROR},
    {F_RESUME | F_FAIL | F_CONTENTRANGE, FETCHE_OK},
    {F_RESUME | F_HTTP416 | F_IGNOREBODY, FETCHE_OK},
    {F_RESUME | F_HTTP416 | F_CONTENTRANGE | F_IGNOREBODY, FETCHE_OK},
    {F_RESUME | F_HTTP416 | F_FAIL | F_IGNOREBODY, FETCHE_OK},
    {F_RESUME | F_HTTP416 | F_FAIL | F_CONTENTRANGE | F_IGNOREBODY,
     FETCHE_OK}};

static int hasbody;

static size_t writedata(char *data, size_t size, size_t nmemb, void *userdata)
{
  (void)data;
  (void)userdata;

  if (size && nmemb)
    hasbody = 1;
  return size * nmemb;
}

static int onetest(FETCH *fetch, const char *url, const struct testparams *p,
                   size_t num)
{
  FETCHcode res;
  unsigned int replyselector;
  char urlbuf[256];

  replyselector = (p->flags & F_CONTENTRANGE) ? 1 : 0;
  if (p->flags & F_HTTP416)
    replyselector += 2;
  msnprintf(urlbuf, sizeof(urlbuf), "%s%04u", url, replyselector);
  test_setopt(fetch, FETCHOPT_URL, urlbuf);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_RESUME_FROM, (p->flags & F_RESUME) ? 3 : 0);
  test_setopt(fetch, FETCHOPT_RANGE, !(p->flags & F_RESUME) ? "3-1000000" : (char *)NULL);
  test_setopt(fetch, FETCHOPT_FAILONERROR, (p->flags & F_FAIL) ? 1 : 0);
  hasbody = 0;
  res = fetch_easy_perform(fetch);
  if (res != p->result)
  {
    printf("%zd: bad error code (%d): resume=%s, fail=%s, http416=%s, "
           "content-range=%s, expected=%d\n",
           num, res,
           (p->flags & F_RESUME) ? "yes" : "no",
           (p->flags & F_FAIL) ? "yes" : "no",
           (p->flags & F_HTTP416) ? "yes" : "no",
           (p->flags & F_CONTENTRANGE) ? "yes" : "no",
           p->result);
    return 1;
  }
  if (hasbody && (p->flags & F_IGNOREBODY))
  {
    printf("body should be ignored and is not: resume=%s, fail=%s, "
           "http416=%s, content-range=%s\n",
           (p->flags & F_RESUME) ? "yes" : "no",
           (p->flags & F_FAIL) ? "yes" : "no",
           (p->flags & F_HTTP416) ? "yes" : "no",
           (p->flags & F_CONTENTRANGE) ? "yes" : "no");
    return 1;
  }
  return 0;

test_cleanup:

  return 1;
}

/* for debugging: */
/* #define SINGLETEST 9 */

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  size_t i;
  int status = 0;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for (i = 0; i < sizeof(testparams) / sizeof(testparams[0]); i++)
  {
    fetch = fetch_easy_init();
    if (!fetch)
    {
      fprintf(stderr, "fetch_easy_init() failed\n");
      fetch_global_cleanup();
      return TEST_ERR_MAJOR_BAD;
    }

    test_setopt(fetch, FETCHOPT_WRITEFUNCTION, writedata);

#ifdef SINGLETEST
    if (SINGLETEST == i)
#endif
      status |= onetest(fetch, URL, testparams + i, i);
    fetch_easy_cleanup(fetch);
  }

  fetch_global_cleanup();
  printf("%d\n", status);
  return (FETCHcode)status;

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
