/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * CUSTOM HTTPS CERTIFICATE REVOCATION CHECK USING CRL
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/stack.h>

static int get_crl_url(X509 *cert, const char **crlUrl)
{
  STACK_OF(DIST_POINT) *dist_points = (STACK_OF(DIST_POINT) *)X509_get_ext_d2i(
    cert, NID_crl_distribution_points, NULL, NULL);
  if(!dist_points) {
    fprintf(stderr, "NO X509_get_ext_d2i found\n");
    return 0;
  }

  for(int j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
    DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
    DIST_POINT_NAME *distpoint = dp->distpoint;
    if(distpoint->type == 0) { /* fullname GENERALIZEDNAME	*/
      for(int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) {
        GENERAL_NAME *gen;
        ASN1_IA5STRING *asn1_str;

        gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
        asn1_str = gen->d.uniformResourceIdentifier;
        *crlUrl = (char *)ASN1_STRING_data(asn1_str);

        return 1;
      }
    }
    else if(distpoint->type == 1) { /* relativename X509NAME */
      STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
      for(int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) {
        X509_NAME_ENTRY *e;
        ASN1_STRING *d;

        e = sk_X509_NAME_ENTRY_value(sk_relname, k);
        d = X509_NAME_ENTRY_get_data(e);

        *crlUrl = (char *)ASN1_STRING_data(d);
        return 1;
      }
    }
  }

  return 0;
}

static CURLcode user_verify_status_callback(CURL *curl, void *s, void *userptr)
{
  SSL *ssl = NULL;
  int chainLength = 0;
  STACK_OF(X509) *ch = NULL;
  unsigned char *status = NULL;
  CURLcode result = CURLE_OK;
  char nameBuffer[256];
  long len;

  (void)curl; /* unused */
  (void)userptr; /* unused */

  fprintf(stdout, "user_verify_status_callback\n");

  ssl = (SSL *)s;
  len = SSL_get_tlsext_status_ocsp_resp(ssl, &status);

  /* ocsp stappling was not received, lets try to download crl and check
   * certificate status using CRL */
  if(!status) {
    fprintf(stdout,
            "SSL_get_tlsext_status_ocsp_resp: ocsp status was not received\n");

    ch = SSL_get_peer_cert_chain(ssl);

    if(!ch) {
      fprintf(stderr, "SSL_get_peer_cert_chain failed\n");
      result = CURLE_SSL_INVALIDCERTSTATUS;
      goto end;
    }

    chainLength = sk_X509_num(ch);

    for(int i = 0; i < chainLength; ++i) {
      const char *crlUrl = NULL;
      const char *ocspUrl = NULL;
      X509 *certificate = sk_X509_value(ch, chainLength - i - 1);

      fprintf(stdout, "Certificate info %i:\n", i);

      fprintf(stdout,
              "\tsubj:   `%s`\n",
              X509_NAME_oneline(X509_get_subject_name(certificate),
                                nameBuffer,
                                sizeof(nameBuffer)));

      fprintf(stdout,
              "\tissuer: `%s`\n",
              X509_NAME_oneline(X509_get_issuer_name(certificate),
                                nameBuffer,
                                sizeof(nameBuffer)));

      if(get_crl_url(certificate, &crlUrl)) {
        fprintf(stdout, "\tCRL url: `%s`\n", crlUrl);

        /* TODO: download CRL, verify its signature and check certificate for
         * revocation */
      }
    }

    goto end;
  }

  /* TODO: do some oscp status verification checks here */

end:
  return result;
}

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://some-site.com");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(
      curl, CURLOPT_SSL_VERIFYSTATUS_FUNCTION, &user_verify_status_callback);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(
        stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
