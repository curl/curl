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
 * Use an in-memory user certificate and RSA key and retrieve an https page.
 * </DESC>
 */
/* Written by Ishan SinghLevett, based on Theo Borm's cacertinmem.c.
 * Note that to maintain simplicity this example does not use a CA certificate
 * for peer verification.  However, some form of peer verification
 * must be used in real circumstances when a secure connection is required.
 */

#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <curl/curl.h>
#include <stdio.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif

static size_t writefunction(void *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return nmemb * size;
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *pointer)
{
  X509 *cert = NULL;
  BIO *bio = NULL;
  BIO *kbio = NULL;
  RSA *rsa = NULL;
  int ret;

  const char *mypem =
    /* replace the XXX with the actual CA certificate */
    "-----BEGIN CERTIFICATE-----\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "-----END CERTIFICATE-----\n";

  /* replace the XXX with the actual RSA key */
  const char *mykey =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
    "-----END RSA PRIVATE KEY-----\n";

  (void)curl;
  (void)pointer;

  /* get a BIO */
  bio = BIO_new_mem_buf((char *)mypem, -1);

  if(!bio) {
    printf("BIO_new_mem_buf failed\n");
  }

  /* use it to read the PEM formatted certificate from memory into an X509
   * structure that SSL can use
   */
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
  if(!cert) {
    printf("PEM_read_bio_X509 failed...\n");
  }

  /* tell SSL to use the X509 certificate */
  ret = SSL_CTX_use_certificate((SSL_CTX*)sslctx, cert);
  if(ret != 1) {
    printf("Use certificate failed\n");
  }

  /* create a bio for the RSA key */
  kbio = BIO_new_mem_buf((char *)mykey, -1);
  if(!kbio) {
    printf("BIO_new_mem_buf failed\n");
  }

  /* read the key bio into an RSA object */
  rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
  if(!rsa) {
    printf("Failed to create key bio\n");
  }

  /* tell SSL to use the RSA key from memory */
  ret = SSL_CTX_use_RSAPrivateKey((SSL_CTX*)sslctx, rsa);
  if(ret != 1) {
    printf("Use Key failed\n");
  }

  /* free resources that have been allocated by OpenSSL functions */
  if(bio)
    BIO_free(bio);

  if(kbio)
    BIO_free(kbio);

  if(rsa)
    RSA_free(rsa);

  if(cert)
    X509_free(cert);

  /* all set to go */
  return CURLE_OK;
}

int main(void)
{
  CURL *ch;
  CURLcode rv;

  curl_global_init(CURL_GLOBAL_ALL);
  ch = curl_easy_init();
  curl_easy_setopt(ch, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(ch, CURLOPT_HEADER, 0L);
  curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, writefunction);
  curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);
  curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, writefunction);
  curl_easy_setopt(ch, CURLOPT_HEADERDATA, stderr);
  curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");

  /* both VERIFYPEER and VERIFYHOST are set to 0 in this case because there is
     no CA certificate */

  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(ch, CURLOPT_URL, "https://www.example.com/");
  curl_easy_setopt(ch, CURLOPT_SSLKEYTYPE, "PEM");

  /* first try: retrieve page without user certificate and key -> fails */
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK) {
    printf("*** transfer succeeded ***\n");
  }
  else {
    printf("*** transfer failed ***\n");
  }

  /* second try: retrieve page using user certificate and key -> succeeds
   * load the certificate and key by installing a function doing the necessary
   * "modifications" to the SSL CONTEXT just before link init
   */
  curl_easy_setopt(ch, CURLOPT_SSL_CTX_FUNCTION, sslctx_function);
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK) {
    printf("*** transfer succeeded ***\n");
  }
  else {
    printf("*** transfer failed ***\n");
  }

  curl_easy_cleanup(ch);
  curl_global_cleanup();
  return (int)rv;
}
