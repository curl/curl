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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

/*
 * Verify correct order of certificates in the chain by comparing the
 * subject and issuer attributes of each certificate.
 */
static bool is_chain_in_order(struct fetch_certinfo *cert_info)
{
  char *last_issuer = NULL;
  int cert;

  /* Chains with only a single certificate are always in order */
  if (cert_info->num_of_certs <= 1)
    return 1;

  /* Enumerate each certificate in the chain */
  for (cert = 0; cert < cert_info->num_of_certs; cert++)
  {
    struct fetch_slist *slist = cert_info->certinfo[cert];
    char *issuer = NULL;
    char *subject = NULL;

    /* Find the certificate issuer and subject by enumerating each field */
    for (; slist && (!issuer || !subject); slist = slist->next)
    {
      const char issuer_prefix[] = "Issuer:";
      const char subject_prefix[] = "Subject:";

      if (!strncmp(slist->data, issuer_prefix, sizeof(issuer_prefix) - 1))
      {
        issuer = slist->data + sizeof(issuer_prefix) - 1;
      }
      if (!strncmp(slist->data, subject_prefix, sizeof(subject_prefix) - 1))
      {
        subject = slist->data + sizeof(subject_prefix) - 1;
      }
    }

    if (subject && issuer)
    {
      printf("cert %d\n", cert);
      printf("  subject: %s\n", subject);
      printf("  issuer: %s\n", issuer);

      if (last_issuer)
      {
        /* If the last certificate's issuer matches the current certificate's
         * subject, then the chain is in order */
        if (strcmp(last_issuer, subject) != 0)
        {
          fprintf(stderr, "cert %d issuer does not match cert %d subject\n",
                  cert - 1, cert);
          fprintf(stderr, "certificate chain is not in order\n");
          return false;
        }
      }
    }

    last_issuer = issuer;
  }

  printf("certificate chain is in order\n");
  return true;
}

static size_t wrfu(void *ptr, size_t size, size_t nmemb, void *stream)
{
  (void)stream;
  (void)ptr;
  return size * nmemb;
}

FETCHcode test(char *URL)
{
  FETCH *fetch;
  FETCHcode res = FETCHE_OK;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Set the HTTPS url to retrieve. */
  test_setopt(fetch, FETCHOPT_URL, URL);

  /* Capture certificate information */
  test_setopt(fetch, FETCHOPT_CERTINFO, 1L);

  /* Ignore output */
  test_setopt(fetch, FETCHOPT_WRITEFUNCTION, wrfu);

  /* No peer verify */
  test_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
  test_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

  /* Perform the request, res will get the return code */
  res = fetch_easy_perform(fetch);
  if (!res || res == FETCHE_GOT_NOTHING)
  {
    struct fetch_certinfo *cert_info = NULL;
    /* Get the certificate information */
    res = fetch_easy_getinfo(fetch, FETCHINFO_CERTINFO, &cert_info);
    if (!res)
    {
      /* Check to see if the certificate chain is ordered correctly */
      if (!is_chain_in_order(cert_info))
        res = TEST_ERR_FAILURE;
    }
  }

test_cleanup:

  /* always cleanup */
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}
