/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * CA cert in memory with OpenSSL to get a HTTPS page.
 * </DESC>
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <stdio.h>

size_t writefunction(void *ptr, size_t size, size_t nmemb, void *stream)
{
  fwrite(ptr, size, nmemb, (FILE *)stream);
  return (nmemb*size);
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
  CURLcode rv = CURLE_ABORTED_BY_CALLBACK; 

  char mypem[] =
  "-----BEGIN CERTIFICATE-----\n" \
  "MIIH0zCCBbugAwIBAgIIXsO3pkN/pOAwDQYJKoZIhvcNAQEFBQAwQjESMBAGA1UE\n" \
  "AwwJQUNDVlJBSVoxMRAwDgYDVQQLDAdQS0lBQ0NWMQ0wCwYDVQQKDARBQ0NWMQsw\n" \
  "CQYDVQQGEwJFUzAeFw0xMTA1MDUwOTM3MzdaFw0zMDEyMzEwOTM3MzdaMEIxEjAQ\n" \
  "BgNVBAMMCUFDQ1ZSQUlaMTEQMA4GA1UECwwHUEtJQUNDVjENMAsGA1UECgwEQUND\n" \
  "VjELMAkGA1UEBhMCRVMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCb\n" \
  "qau/YUqXry+XZpp0X9DZlv3P4uRm7x8fRzPCRKPfmt4ftVTdFXxpNRFvu8gMjmoY\n" \
  "HtiP2Ra8EEg2XPBjs5BaXCQ316PWywlxufEBcoSwfdtNgM3802/J+Nq2DoLSRYWo\n" \
  "G2ioPej0RGy9ocLLA76MPhMAhN9KSMDjIgro6TenGEyxCQ0jVn8ETdkXhBilyNpA\n" \
  "lHPrzg5XPAOBOp0KoVdDaaxXbXmQeOW1tDvYvEyNKKGno6e6Ak4l0Squ7a4DIrhr\n" \
  "IA8wKFSVf+DuzgpmndFALW4ir50awQUZ0m/A8p/4e7MCQvtQqR0tkw8jq8bBD5L/\n" \
  "0KIV9VMJcRz/RROE5iZe+OCIHAr8Fraocwa48GOEAqDGWuzndN9wrqODJerWx5eH\n" \
  "k6fGioozl2A3ED6XPm4pFdahD9GILBKfb6qkxkLrQaLjlUPTAYVtjrs78yM2x/47\n" \
  "4KElB0iryYl0/wiPgL/AlmXz7uxLaL2diMMxs0Dx6M/2OLuc5NF/1OVYm3z61PMO\n" \
  "m3WR5LpSLhl+0fXNWhn8ugb2+1KoS5kE3fj5tItQo05iifCHJPqDQsGH+tUtKSpa\n" \
  "cXpkatcnYGMN285J9Y0fkIkyF/hzQ7jSWpOGYdbhdQrqeWZ2iE9x6wQl1gpaepPl\n" \
  "uUsXQA+xtrn13k/c4LOsOxFwYIRKQ26ZIMApcQrAZQIDAQABo4ICyzCCAscwfQYI\n" \
  "KwYBBQUHAQEEcTBvMEwGCCsGAQUFBzAChkBodHRwOi8vd3d3LmFjY3YuZXMvZmls\n" \
  "ZWFkbWluL0FyY2hpdm9zL2NlcnRpZmljYWRvcy9yYWl6YWNjdjEuY3J0MB8GCCsG\n" \
  "AQUFBzABhhNodHRwOi8vb2NzcC5hY2N2LmVzMB0GA1UdDgQWBBTSh7Tj3zcnk1X2\n" \
  "VuqB5TbMjB4/vTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNKHtOPfNyeT\n" \
  "VfZW6oHlNsyMHj+9MIIBcwYDVR0gBIIBajCCAWYwggFiBgRVHSAAMIIBWDCCASIG\n" \
  "CCsGAQUFBwICMIIBFB6CARAAQQB1AHQAbwByAGkAZABhAGQAIABkAGUAIABDAGUA\n" \
  "cgB0AGkAZgBpAGMAYQBjAGkA8wBuACAAUgBhAO0AegAgAGQAZQAgAGwAYQAgAEEA\n" \
  "QwBDAFYAIAAoAEEAZwBlAG4AYwBpAGEAIABkAGUAIABUAGUAYwBuAG8AbABvAGcA\n" \
  "7QBhACAAeQAgAEMAZQByAHQAaQBmAGkAYwBhAGMAaQDzAG4AIABFAGwAZQBjAHQA\n" \
  "cgDzAG4AaQBjAGEALAAgAEMASQBGACAAUQA0ADYAMAAxADEANQA2AEUAKQAuACAA\n" \
  "QwBQAFMAIABlAG4AIABoAHQAdABwADoALwAvAHcAdwB3AC4AYQBjAGMAdgAuAGUA\n" \
  "czAwBggrBgEFBQcCARYkaHR0cDovL3d3dy5hY2N2LmVzL2xlZ2lzbGFjaW9uX2Mu\n" \
  "aHRtMFUGA1UdHwROMEwwSqBIoEaGRGh0dHA6Ly93d3cuYWNjdi5lcy9maWxlYWRt\n" \
  "aW4vQXJjaGl2b3MvY2VydGlmaWNhZG9zL3JhaXphY2N2MV9kZXIuY3JsMA4GA1Ud\n" \
  "DwEB/wQEAwIBBjAXBgNVHREEEDAOgQxhY2N2QGFjY3YuZXMwDQYJKoZIhvcNAQEF\n" \
  "BQADggIBAJcxAp/n/UNnSEQU5CmH7UwoZtCPNdpNYbdKl02125DgBS4OxnnQ8pdp\n" \
  "D70ER9m+27Up2pvZrqmZ1dM8MJP1jaGo/AaNRPTKFpV8M9xii6g3+CfYCS0b78gU\n" \
  "JyCpZET/LtZ1qmxNYEAZSUNUY9rizLpm5U9EelvZaoErQNV/+QEnWCzI7UiRfD+m\n" \
  "AM/EKXMRNt6GGT6d7hmKG9Ww7Y49nCrADdg9ZuM8Db3VlFzi4qc1GwQA9j9ajepD\n" \
  "vV+JHanBsMyZ4k0ACtrJJ1vnE5Bc5PUzolVt3OAJTS+xJlsndQAJxGJ3KQhfnlms\n" \
  "tn6tn1QwIgPBHnFk/vk4CpYY3QIUrCPLBhwepH2NDd4nQeit2hW3sCPdK6jT2iWH\n" \
  "7ehVRE2I9DZ+hJp4rPcOVkkO1jMl1oRQQmwgEh0q1b688nCBpHBgvgW1m54ERL5h\n" \
  "I6zppSSMEYCUWqKiuUnSwdzRp+0xESyeGabu4VXhwOrPDYTkF7eifKXeVSUG7szA\n" \
  "h1xA2syVP1XgNce4hL60Xc16gwFy7ofmXx2utYXGJt/mwZrpHgJHnyqobalbz+xF\n" \
  "d3+YJ5oyXSrjhO7FmGYvliAd3djDJ9ew+f7Zfc3Qn48LFFhRny+Lwzgt3uiP1o2H\n" \
  "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7\n" \
  "-----END CERTIFICATE-----\n" \
  "-----BEGIN CERTIFICATE-----\n" \
  "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\n" \
  "Z05phkOTOPu220+DkdRgfks+KzgHVZhepA==\n" \
  "-----END CERTIFICATE-----";

    BIO *cbio = BIO_new_mem_buf(mypem, sizeof(mypem));
    X509_STORE  *cts = SSL_CTX_get_cert_store((SSL_CTX *)sslctx);
    if(!cts || !cbio)
    {
        return rv;
    }
    
    X509_INFO *itmp;
    int i, count = 0, type = X509_FILETYPE_PEM;
    STACK_OF(X509_INFO) *inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf)
    {
        BIO_free(cbio);//cleanup
        return rv;
    }
    //itterate over all entries from the pem file, add them to the x509_store one by one
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            X509_STORE_add_cert(cts, itmp->x509);
            count++;
        }
        if (itmp->crl) {
            X509_STORE_add_crl(cts, itmp->crl);
            count++;
        }
    }
    sk_X509_INFO_pop_free(inf, X509_INFO_free); //cleanup
    BIO_free(cbio);//cleanup

    rv = CURLE_OK;
    return rv;
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
  rv = curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, *writefunction);
  rv = curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);
  rv = curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, *writefunction);
  rv = curl_easy_setopt(ch, CURLOPT_HEADERDATA, stderr);
  rv = curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");
  rv = curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);
  rv = curl_easy_setopt(ch, CURLOPT_URL, "https://www.example.com/");

  /* turn off the default CA locations (optional)
   * otherwise libcurl will load CA certificates from the locations that
   * were detected/specified at build-time
   */
  rv = curl_easy_setopt(ch, CURLOPT_CAINFO, NULL);
  rv = curl_easy_setopt(ch, CURLOPT_CAPATH, NULL);

  /* first try: retrieve page without ca certificates -> should fail
   * unless libcurl was built --with-ca-fallback enabled at build-time
   */
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK)
    printf("*** transfer succeeded ***\n");
  else
    printf("*** transfer failed ***\n");

  /* use a fresh connection (optional)
   * this option seriously impacts performance of multiple transfers but
   * it is necessary order to demonstrate this example. recall that the
   * ssl ctx callback is only called _before_ an SSL connection is
   * established, therefore it will not affect existing verified SSL
   * connections already in the connection cache associated with this
   * handle. normally you would set the ssl ctx function before making
   * any transfers, and not use this option.
   */
  rv = curl_easy_setopt(ch, CURLOPT_FRESH_CONNECT, 1L);

  /* second try: retrieve page using cacerts' certificate -> will succeed
   * load the certificate by installing a function doing the necessary
   * "modifications" to the SSL CONTEXT just before link init
   */
  rv = curl_easy_setopt(ch, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
  rv = curl_easy_perform(ch);
  if(rv == CURLE_OK)
    printf("*** transfer succeeded ***\n");
  else
    printf("*** transfer failed ***\n");

  curl_easy_cleanup(ch);
  curl_global_cleanup();
  return rv;
}
