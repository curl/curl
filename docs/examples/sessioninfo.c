/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Uses the CURLINFO_TLS_SESSION data.
 * </DESC>
 */

/* Note that this example currently requires curl to be linked against
   GnuTLS (and this program must also be linked against -lgnutls). */

#include <stdio.h>

#include <curl/curl.h>
#include <gnutls/gnutls.h>

static CURL *curl;

static size_t wrfu(void *ptr, size_t size, size_t nmemb, void *stream)
{
  const struct curl_tlssessioninfo *info;
  unsigned int cert_list_size;
  const gnutls_datum_t *chainp;
  CURLcode res;

  (void)stream;
  (void)ptr;

  res = curl_easy_getinfo(curl, CURLINFO_TLS_SESSION, &info);

  if(!res) {
    switch(info->backend) {
    case CURLSSLBACKEND_GNUTLS:
      /* info->internals is now the gnutls_session_t */
      chainp = gnutls_certificate_get_peers(info->internals, &cert_list_size);
      if((chainp) && (cert_list_size)) {
        unsigned int i;

        for(i = 0; i < cert_list_size; i++) {
          gnutls_x509_crt_t cert;
          gnutls_datum_t dn;

          if(GNUTLS_E_SUCCESS == gnutls_x509_crt_init(&cert)) {
            if(GNUTLS_E_SUCCESS ==
               gnutls_x509_crt_import(cert, &chainp[i], GNUTLS_X509_FMT_DER)) {
              if(GNUTLS_E_SUCCESS ==
                 gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &dn)) {
                fprintf(stderr, "Certificate #%u: %.*s", i, dn.size, dn.data);

                gnutls_free(dn.data);
              }
            }

            gnutls_x509_crt_deinit(cert);
          }
        }
      }
      break;
    case CURLSSLBACKEND_NONE:
    default:
      break;
    }
  }

  return size * nmemb;
}

int main(void)
{
  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wrfu);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

    (void) curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return 0;
}
