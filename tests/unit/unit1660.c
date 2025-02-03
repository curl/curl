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
#include "fetchcheck.h"

#include "urldata.h"
#include "hsts.h"

static FETCHcode
unit_setup(void)
{
  return FETCHE_OK;
}

static void
unit_stop(void)
{
  fetch_global_cleanup();
}

#if defined(FETCH_DISABLE_HTTP) || defined(FETCH_DISABLE_HSTS)
UNITTEST_START
{
  puts("nothing to do when HTTP or HSTS are disabled");
}
UNITTEST_STOP
#else

struct testit
{
  const char *host;
  const char *chost;      /* if non-NULL, use to lookup with */
  const char *hdr;        /* if NULL, just do the lookup */
  const FETCHcode result; /* parse result */
};

static const struct testit headers[] = {
    /* two entries read from disk cache, verify first */
    {"-", "readfrom.example", NULL, FETCHE_OK},
    {"-", "old.example", NULL, FETCHE_OK},
    /* delete the remaining one read from disk */
    {"readfrom.example", NULL, "max-age=\"0\"", FETCHE_OK},

    {"example.com", NULL, "max-age=\"31536000\"\r\n", FETCHE_OK},
    {"example.com", NULL, "max-age=\"21536000\"\r\n", FETCHE_OK},
    {"example.com", NULL, "max-age=\"21536000\"; \r\n", FETCHE_OK},
    {"example.com", NULL, "max-age=\"21536000\"; includeSubDomains\r\n",
     FETCHE_OK},
    {"example.org", NULL, "max-age=\"31536000\"\r\n", FETCHE_OK},
    {"this.example", NULL, "max=\"31536\";", FETCHE_BAD_FUNCTION_ARGUMENT},
    {"this.example", NULL, "max-age=\"31536", FETCHE_BAD_FUNCTION_ARGUMENT},
    {"this.example", NULL, "max-age=31536\"", FETCHE_OK},
    /* max-age=0 removes the entry */
    {"this.example", NULL, "max-age=0", FETCHE_OK},
    {"another.example", NULL, "includeSubDomains; ",
     FETCHE_BAD_FUNCTION_ARGUMENT},

    /* Two max-age is illegal */
    {"example.com", NULL,
     "max-age=\"21536000\"; includeSubDomains; max-age=\"3\";",
     FETCHE_BAD_FUNCTION_ARGUMENT},
    /* Two includeSubDomains is illegal */
    {"2.example.com", NULL,
     "max-age=\"21536000\"; includeSubDomains; includeSubDomains;",
     FETCHE_BAD_FUNCTION_ARGUMENT},
    /* use a unknown directive "include" that should be ignored */
    {"3.example.com", NULL, "max-age=\"21536000\"; include; includeSubDomains;",
     FETCHE_OK},
    /* remove the "3.example.com" one, should still match the example.com */
    {"3.example.com", NULL, "max-age=\"0\"; includeSubDomains;",
     FETCHE_OK},
    {"-", "foo.example.com", NULL, FETCHE_OK},
    {"-", "foo.xample.com", NULL, FETCHE_OK},

    /* should not match */
    {"example.net", "forexample.net", "max-age=\"31536000\"\r\n", FETCHE_OK},

    /* should not match either, since forexample.net is not in the example.net
       domain */
    {"example.net", "forexample.net",
     "max-age=\"31536000\"; includeSubDomains\r\n", FETCHE_OK},
    /* remove example.net again */
    {"example.net", NULL, "max-age=\"0\"; includeSubDomains\r\n", FETCHE_OK},

    /* make this live for 7 seconds */
    {"expire.example", NULL, "max-age=\"7\"\r\n", FETCHE_OK},
    {NULL, NULL, NULL, FETCHE_OK}};

static void showsts(struct stsentry *e, const char *chost)
{
  if (!e)
    printf("'%s' is not HSTS\n", chost);
  else
  {
    printf("%s [%s]: %" FETCH_FORMAT_FETCH_OFF_T "%s\n",
           chost, e->host, e->expires,
           e->includeSubDomains ? " includeSubDomains" : "");
  }
}

UNITTEST_START
{
  FETCHcode result;
  struct stsentry *e;
  struct hsts *h = Fetch_hsts_init();
  int i;
  const char *chost;
  FETCH *easy;
  char savename[256];

  abort_unless(h, "Fetch_hsts_init()");

  fetch_global_init(FETCH_GLOBAL_ALL);
  easy = fetch_easy_init();
  if (!easy)
  {
    Fetch_hsts_cleanup(&h);
    fetch_global_cleanup();
    abort_unless(easy, "fetch_easy_init()");
  }

  Fetch_hsts_loadfile(easy, h, arg);

  for (i = 0; headers[i].host; i++)
  {
    if (headers[i].hdr)
    {
      result = Fetch_hsts_parse(h, headers[i].host, headers[i].hdr);

      if (result != headers[i].result)
      {
        fprintf(stderr, "Fetch_hsts_parse(%s) failed: %d\n",
                headers[i].hdr, result);
        unitfail++;
        continue;
      }
      else if (result)
      {
        printf("Input %u: error %d\n", i, (int)result);
        continue;
      }
    }

    chost = headers[i].chost ? headers[i].chost : headers[i].host;
    e = Fetch_hsts(h, chost, strlen(chost), TRUE);
    showsts(e, chost);
  }

  printf("Number of entries: %zu\n", Fetch_llist_count(&h->list));

  /* verify that it is exists for 7 seconds */
  chost = "expire.example";
  for (i = 100; i < 110; i++)
  {
    e = Fetch_hsts(h, chost, strlen(chost), TRUE);
    showsts(e, chost);
    deltatime++; /* another second passed */
  }

  msnprintf(savename, sizeof(savename), "%s.save", arg);
  (void)Fetch_hsts_save(easy, h, savename);
  Fetch_hsts_cleanup(&h);
  fetch_easy_cleanup(easy);
  fetch_global_cleanup();
}
UNITTEST_STOP
#endif
