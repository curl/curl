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
/* <DESC>
 * Shows HTTPS usage with client certs and optional ssl engine use.
 * </DESC>
 */
#include <stdio.h>

#include <fetch/fetch.h>

/* some requirements for this to work:
   1.   set pCertFile to the file with the client certificate
   2.   if the key is passphrase protected, set pPassphrase to the
        passphrase you use
   3.   if you are using a crypto engine:
   3.1. set a #define USE_ENGINE
   3.2. set pEngine to the name of the crypto engine you use
   3.3. set pKeyName to the key identifier you want to use
   4.   if you do not use a crypto engine:
   4.1. set pKeyName to the filename of your client key
   4.2. if the format of the key file is DER, set pKeyType to "DER"

   !! verify of the server certificate is not implemented here !!

   **** This example only works with libfetch 7.9.3 and later! ****

*/

int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  FILE *headerfile;
  const char *pPassphrase = NULL;

  static const char *pCertFile = "testcert.pem";
  static const char *pCACertFile = "cacert.pem";
  static const char *pHeaderFile = "dumpit";

  const char *pKeyName;
  const char *pKeyType;

  const char *pEngine;

#ifdef USE_ENGINE
  pKeyName  = "rsa_test";
  pKeyType  = "ENG";
  pEngine   = "chil";            /* for nChiper HSM... */
#else
  pKeyName  = "testkey.pem";
  pKeyType  = "PEM";
  pEngine   = NULL;
#endif

  headerfile = fopen(pHeaderFile, "wb");
  if(!headerfile)
    return 1;

  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  fetch = fetch_easy_init();
  if(fetch) {
    /* what call to write: */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "HTTPS://your.favourite.ssl.site");
    fetch_easy_setopt(fetch, FETCHOPT_HEADERDATA, headerfile);

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127)  /* conditional expression is constant */
#endif
    do { /* dummy loop, just to break out from */
      if(pEngine) {
        /* use crypto engine */
        if(fetch_easy_setopt(fetch, FETCHOPT_SSLENGINE, pEngine) != FETCHE_OK) {
          /* load the crypto engine */
          fprintf(stderr, "cannot set crypto engine\n");
          break;
        }
        if(fetch_easy_setopt(fetch, FETCHOPT_SSLENGINE_DEFAULT, 1L) != FETCHE_OK) {
          /* set the crypto engine as default */
          /* only needed for the first time you load
             an engine in a fetch object... */
          fprintf(stderr, "cannot set crypto engine as default\n");
          break;
        }
      }
      /* cert is stored PEM coded in file... */
      /* since PEM is default, we needn't set it for PEM */
      fetch_easy_setopt(fetch, FETCHOPT_SSLCERTTYPE, "PEM");

      /* set the cert for client authentication */
      fetch_easy_setopt(fetch, FETCHOPT_SSLCERT, pCertFile);

      /* sorry, for engine we must set the passphrase
         (if the key has one...) */
      if(pPassphrase)
        fetch_easy_setopt(fetch, FETCHOPT_KEYPASSWD, pPassphrase);

      /* if we use a key stored in a crypto engine,
         we must set the key type to "ENG" */
      fetch_easy_setopt(fetch, FETCHOPT_SSLKEYTYPE, pKeyType);

      /* set the private key (file or ID in engine) */
      fetch_easy_setopt(fetch, FETCHOPT_SSLKEY, pKeyName);

      /* set the file with the certs validating the server */
      fetch_easy_setopt(fetch, FETCHOPT_CAINFO, pCACertFile);

      /* disconnect if we cannot validate server's cert */
      fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 1L);

      /* Perform the request, res gets the return code */
      res = fetch_easy_perform(fetch);
      /* Check for errors */
      if(res != FETCHE_OK)
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));

      /* we are done... */
    } while(0);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }

  fetch_global_cleanup();

  fclose(headerfile);

  return 0;
}
