/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
/* <DESC>
 * Shows HTTPS usage with client certs and optional ssl engine use.
 * </DESC>
 */
#include <stdio.h>

#include <curl/curl.h>

/* some requirements for this to work:
   1.   set pCertFile to the file with the client certificate
   2.   if the key is passphrase protected, set pPassphrase to the
        passphrase you use
   3.   if you are using a crypto engine:
   3.1. set a #define USE_ENGINE
   3.2. set pEngine to the name of the crypto engine you use
   3.3. set pKeyName to the key identifier you want to use
   4.   if you do not use a crypto engine:
   4.1. set pKeyName to the file name of your client key
   4.2. if the format of the key file is DER, set pKeyType to "DER"

   !! verify of the server certificate is not implemented here !!

   **** This example only works with libcurl 7.9.3 and later! ****

*/

int main(void)
{
  CURL *curl;
  CURLcode res;
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

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    /* what call to write: */
    curl_easy_setopt(curl, CURLOPT_URL, "HTTPS://your.favourite.ssl.site");
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, headerfile);

    do { /* dummy loop, just to break out from */
      if(pEngine) {
        /* use crypto engine */
        if(curl_easy_setopt(curl, CURLOPT_SSLENGINE, pEngine) != CURLE_OK) {
          /* load the crypto engine */
          fprintf(stderr, "cannot set crypto engine\n");
          break;
        }
        if(curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK) {
          /* set the crypto engine as default */
          /* only needed for the first time you load
             a engine in a curl object... */
          fprintf(stderr, "cannot set crypto engine as default\n");
          break;
        }
      }
      /* cert is stored PEM coded in file... */
      /* since PEM is default, we needn't set it for PEM */
      curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");

      /* set the cert for client authentication */
      curl_easy_setopt(curl, CURLOPT_SSLCERT, pCertFile);

      /* sorry, for engine we must set the passphrase
         (if the key has one...) */
      if(pPassphrase)
        curl_easy_setopt(curl, CURLOPT_KEYPASSWD, pPassphrase);

      /* if we use a key stored in a crypto engine,
         we must set the key type to "ENG" */
      curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, pKeyType);

      /* set the private key (file or ID in engine) */
      curl_easy_setopt(curl, CURLOPT_SSLKEY, pKeyName);

      /* set the file with the certs vaildating the server */
      curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);

      /* disconnect if we cannot validate server's cert */
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

      /* Perform the request, res will get the return code */
      res = curl_easy_perform(curl);
      /* Check for errors */
      if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));

      /* we are done... */
    } while(0);
    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
