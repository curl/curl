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
   4.1. set pKeyName to the filename of your client key
   4.2. if the format of the key file is DER, set pKeyType to "DER"

   !! verify of the server certificate is not implemented here !!

   **** This example only works with libcurl 7.9.3 and later! ****

*/

int main(void)
{
  CURL *curl = NULL;
  CURLcode res;
  FILE *headerfile;
  const char *pPassphrase = NULL;

  static const char *pCertFile = "testcert.pem";
  static const char *pCACertFile = "cacert.pem";
  static const char *pHeaderFile = "dumpit";

  const char *pKeyName;
  const char *pKeyType;

#ifdef USE_ENGINE
  pKeyName  = "rsa_test";
  pKeyType  = "ENG";
#else
  pKeyName  = "testkey.pem";
  pKeyType  = "PEM";
#endif

  res = curl_global_init(CURL_GLOBAL_ALL);
  if(res) {
    return (int)res;
  }

  headerfile = fopen(pHeaderFile, "wb");
  if(!headerfile)
    goto error;

  curl = curl_easy_init();
  if(!curl)
    goto error;

  /* what call to write: */
  curl_easy_setopt(curl, CURLOPT_URL, "HTTPS://secure.site.example");
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, headerfile);

#ifdef USE_ENGINE
  /* use crypto engine. nCipher HSM... */
  if(curl_easy_setopt(curl, CURLOPT_SSLENGINE, "chil") != CURLE_OK) {
    /* load the crypto engine */
    fprintf(stderr, "cannot set crypto engine\n");
    goto error;
  }
  if(curl_easy_setopt(curl, CURLOPT_SSLENGINE_DEFAULT, 1L) != CURLE_OK) {
    /* set the crypto engine as default */
    /* only needed for the first time you load
       an engine in a curl object... */
    fprintf(stderr, "cannot set crypto engine as default\n");
    goto error;
  }
#endif

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

  /* set the file with the certs validating the server */
  curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);

  /* disconnect if we cannot validate server's cert */
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

  /* Perform the request, res gets the return code */
  res = curl_easy_perform(curl);
  /* Check for errors */
  if(res != CURLE_OK)
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));

error:

  /* always cleanup */
  if(curl)
    curl_easy_cleanup(curl);

  if(headerfile)
    fclose(headerfile);

  curl_global_cleanup();

  return (int)res;
}
