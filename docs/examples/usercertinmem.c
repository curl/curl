/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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
 * Use an in-memory user certificate and RSA key and retrieve an https page.
 * </DESC>
 */
/* Written by Ishan SinghLevett, based on Theo Borm's cacertinmem.c.
 * Note that to maintain simplicity this example does not use a CA certificate
 * for peer verification.  However, some form of peer verification
 * must be used in real circumstances when a secure connection is required.
 */

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <curl/curl.h>
#include <stdio.h>

static size_t writefunction(void *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, stream);
  return (nmemb*size);
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
  X509 *cert = NULL;
  BIO *bio = NULL;
  BIO *kbio = NULL;
  RSA *rsa = NULL;
  int ret;

  const char *mypem = /* www.cacert.org */
    "-----BEGIN CERTIFICATE-----\n"\
    "MIIHPTCCBSWgAwIBAgIBADANBgkqhkiG9w0BAQQFADB5MRAwDgYDVQQKEwdSb290\n"\
    "IENBMR4wHAYDVQQLExVodHRwOi8vd3d3LmNhY2VydC5vcmcxIjAgBgNVBAMTGUNB\n"\
    "IENlcnQgU2lnbmluZyBBdXRob3JpdHkxITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRA\n"\
    "Y2FjZXJ0Lm9yZzAeFw0wMzAzMzAxMjI5NDlaFw0zMzAzMjkxMjI5NDlaMHkxEDAO\n"\
    "BgNVBAoTB1Jvb3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEi\n"\
    "MCAGA1UEAxMZQ0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJ\n"\
    "ARYSc3VwcG9ydEBjYWNlcnQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\n"\
    "CgKCAgEAziLA4kZ97DYoB1CW8qAzQIxL8TtmPzHlawI229Z89vGIj053NgVBlfkJ\n"\
    "8BLPRoZzYLdufujAWGSuzbCtRRcMY/pnCujW0r8+55jE8Ez64AO7NV1sId6eINm6\n"\
    "zWYyN3L69wj1x81YyY7nDl7qPv4coRQKFWyGhFtkZip6qUtTefWIonvuLwphK42y\n"\
    "fk1WpRPs6tqSnqxEQR5YYGUFZvjARL3LlPdCfgv3ZWiYUQXw8wWRBB0bF4LsyFe7\n"\
    "w2t6iPGwcswlWyCR7BYCEo8y6RcYSNDHBS4CMEK4JZwFaz+qOqfrU0j36NK2B5jc\n"\
    "G8Y0f3/JHIJ6BVgrCFvzOKKrF11myZjXnhCLotLddJr3cQxyYN/Nb5gznZY0dj4k\n"\
    "epKwDpUeb+agRThHqtdB7Uq3EvbXG4OKDy7YCbZZ16oE/9KTfWgu3YtLq1i6L43q\n"\
    "laegw1SJpfvbi1EinbLDvhG+LJGGi5Z4rSDTii8aP8bQUWWHIbEZAWV/RRyH9XzQ\n"\
    "QUxPKZgh/TMfdQwEUfoZd9vUFBzugcMd9Zi3aQaRIt0AUMyBMawSB3s42mhb5ivU\n"\
    "fslfrejrckzzAeVLIL+aplfKkQABi6F1ITe1Yw1nPkZPcCBnzsXWWdsC4PDSy826\n"\
    "YreQQejdIOQpvGQpQsgi3Hia/0PsmBsJUUtaWsJx8cTLc6nloQsCAwEAAaOCAc4w\n"\
    "ggHKMB0GA1UdDgQWBBQWtTIb1Mfz4OaO873SsDrusjkY0TCBowYDVR0jBIGbMIGY\n"\
    "gBQWtTIb1Mfz4OaO873SsDrusjkY0aF9pHsweTEQMA4GA1UEChMHUm9vdCBDQTEe\n"\
    "MBwGA1UECxMVaHR0cDovL3d3dy5jYWNlcnQub3JnMSIwIAYDVQQDExlDQSBDZXJ0\n"\
    "IFNpZ25pbmcgQXV0aG9yaXR5MSEwHwYJKoZIhvcNAQkBFhJzdXBwb3J0QGNhY2Vy\n"\
    "dC5vcmeCAQAwDwYDVR0TAQH/BAUwAwEB/zAyBgNVHR8EKzApMCegJaAjhiFodHRw\n"\
    "czovL3d3dy5jYWNlcnQub3JnL3Jldm9rZS5jcmwwMAYJYIZIAYb4QgEEBCMWIWh0\n"\
    "dHBzOi8vd3d3LmNhY2VydC5vcmcvcmV2b2tlLmNybDA0BglghkgBhvhCAQgEJxYl\n"\
    "aHR0cDovL3d3dy5jYWNlcnQub3JnL2luZGV4LnBocD9pZD0xMDBWBglghkgBhvhC\n"\
    "AQ0ESRZHVG8gZ2V0IHlvdXIgb3duIGNlcnRpZmljYXRlIGZvciBGUkVFIGhlYWQg\n"\
    "b3ZlciB0byBodHRwOi8vd3d3LmNhY2VydC5vcmcwDQYJKoZIhvcNAQEEBQADggIB\n"\
    "ACjH7pyCArpcgBLKNQodgW+JapnM8mgPf6fhjViVPr3yBsOQWqy1YPaZQwGjiHCc\n"\
    "nWKdpIevZ1gNMDY75q1I08t0AoZxPuIrA2jxNGJARjtT6ij0rPtmlVOKTV39O9lg\n"\
    "18p5aTuxZZKmxoGCXJzN600BiqXfEVWqFcofN8CCmHBh22p8lqOOLlQ+TyGpkO/c\n"\
    "gr/c6EWtTZBzCDyUZbAEmXZ/4rzCahWqlwQ3JNgelE5tDlG+1sSPypZt90Pf6DBl\n"\
    "Jzt7u0NDY8RD97LsaMzhGY4i+5jhe1o+ATc7iwiwovOVThrLm82asduycPAtStvY\n"\
    "sONvRUgzEv/+PDIqVPfE94rwiCPCR/5kenHA0R6mY7AHfqQv0wGP3J8rtsYIqQ+T\n"\
    "SCX8Ev2fQtzzxD72V7DX3WnRBnc0CkvSyqD/HMaMyRa+xMwyN2hzXwj7UfdJUzYF\n"\
    "CpUCTPJ5GhD22Dp1nPMd8aINcGeGG7MW9S/lpOt5hvk9C8JzC6WZrG/8Z7jlLwum\n"\
    "GCSNe9FINSkYQKyTYOGWhlC0elnYjyELn8+CkcY7v2vcB5G5l1YjqrZslMZIBjzk\n"\
    "zk6q5PYvCdxTby78dOs6Y5nCpqyJvKeyRKANihDjbPIky/qbn3BHLt4Ui9SyIAmW\n"\
    "omTxJBzcoTWcFbLUvFUufQb1nA5V9FrWk9p2rSVzTMVD\n"\
    "-----END CERTIFICATE-----\n";

/*replace the XXX with the actual RSA key*/
  const char *mykey =
    "-----BEGIN RSA PRIVATE KEY-----\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"\
    "-----END RSA PRIVATE KEY-----\n";

  (void)curl; /* avoid warnings */
  (void)parm; /* avoid warnings */

  /* get a BIO */
  bio = BIO_new_mem_buf((char *)mypem, -1);

  if(bio == NULL) {
    printf("BIO_new_mem_buf failed\n");
  }

  /* use it to read the PEM formatted certificate from memory into an X509
   * structure that SSL can use
   */
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
  if(cert == NULL) {
    printf("PEM_read_bio_X509 failed...\n");
  }

  /*tell SSL to use the X509 certificate*/
  ret = SSL_CTX_use_certificate((SSL_CTX*)sslctx, cert);
  if(ret != 1) {
    printf("Use certificate failed\n");
  }

  /*create a bio for the RSA key*/
  kbio = BIO_new_mem_buf((char *)mykey, -1);
  if(kbio == NULL) {
    printf("BIO_new_mem_buf failed\n");
  }

  /*read the key bio into an RSA object*/
  rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
  if(rsa == NULL) {
    printf("Failed to create key bio\n");
  }

  /*tell SSL to use the RSA key from memory*/
  ret = SSL_CTX_use_RSAPrivateKey((SSL_CTX*)sslctx, rsa);
  if(ret != 1) {
    printf("Use Key failed\n");
  }

  /* free resources that have been allocated by openssl functions */
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

  rv = curl_global_init(CURL_GLOBAL_ALL);
  ch = curl_easy_init();
  rv = curl_easy_setopt(ch, CURLOPT_VERBOSE, 0L);
  rv = curl_easy_setopt(ch, CURLOPT_HEADER, 0L);
  rv = curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
  rv = curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
  rv = curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, writefunction);
  rv = curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);
  rv = curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, writefunction);
  rv = curl_easy_setopt(ch, CURLOPT_HEADERDATA, stderr);
  rv = curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");

  /* both VERIFYPEER and VERIFYHOST are set to 0 in this case because there is
     no CA certificate*/

  rv = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
  rv = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
  rv = curl_easy_setopt(ch, CURLOPT_URL, "https://www.example.com/");
  rv = curl_easy_setopt(ch, CURLOPT_SSLKEYTYPE, "PEM");

  /* first try: retrieve page without user certificate and key -> will fail
   */
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK) {
    printf("*** transfer succeeded ***\n");
  }
  else {
    printf("*** transfer failed ***\n");
  }

  /* second try: retrieve page using user certificate and key -> will succeed
   * load the certificate and key by installing a function doing the necessary
   * "modifications" to the SSL CONTEXT just before link init
   */
  rv = curl_easy_setopt(ch, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK) {
    printf("*** transfer succeeded ***\n");
  }
  else {
    printf("*** transfer failed ***\n");
  }

  curl_easy_cleanup(ch);
  curl_global_cleanup();
  return rv;
}
