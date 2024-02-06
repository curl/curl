---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_CTX_FUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_CTX_DATA (3)
  - CURLOPT_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_SSL_CTX_FUNCTION - SSL context callback for OpenSSL, wolfSSL or mbedTLS

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *clientp);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_CTX_FUNCTION,
                          ssl_ctx_callback);
~~~

# DESCRIPTION

This option only works for libcurl powered by OpenSSL, wolfSSL, mbedTLS or
BearSSL. If libcurl was built against another SSL library this functionality
is absent.

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libcurl just before the initialization
of an SSL connection after having processed all other SSL related options to
give a last chance to an application to modify the behavior of the SSL
initialization. The *ssl_ctx* parameter is actually a pointer to the SSL
library's *SSL_CTX* for OpenSSL or wolfSSL, a pointer to
*mbedtls_ssl_config* for mbedTLS or a pointer to
*br_ssl_client_context* for BearSSL. If an error is returned from the
callback no attempt to establish a connection is made and the perform
operation returns the callback's error code. Set the *clientp* argument
with the CURLOPT_SSL_CTX_DATA(3) option.

This function gets called on all new connections made to a server, during the
SSL negotiation. The *ssl_ctx* points to a newly initialized object each
time, but note the pointer may be the same as from a prior call.

To use this properly, a non-trivial amount of knowledge of your SSL library is
necessary. For example, you can use this function to call library-specific
callbacks to add additional validation code for certificates, and even to
change the actual URI of an HTTPS request.

For OpenSSL, asynchronous certificate verification via
*SSL_set_retry_verify* is supported. (Added in 8.3.0)

WARNING: The CURLOPT_SSL_CTX_FUNCTION(3) callback allows the application
to reach in and modify SSL details in the connection without libcurl itself
knowing anything about it, which then subsequently can lead to libcurl
unknowingly reusing SSL connections with different properties. To remedy this
you may set CURLOPT_FORBID_REUSE(3) from the callback function.

WARNING: If you are using DNS-over-HTTPS (DoH) via CURLOPT_DOH_URL(3)
then this callback is also called for those transfers and the curl handle is
set to an internal handle. **This behavior is subject to change.** We
recommend before performing your transfer set CURLOPT_PRIVATE(3) on your
curl handle so you can identify it in the context callback. If you have a
reason to modify DoH SSL context please let us know on the curl-library
mailing list because we are considering removing this capability.

# DEFAULT

NULL

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
/* OpenSSL specific */

#include <openssl/ssl.h>
#include <curl/curl.h>
#include <stdio.h>

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
  X509_STORE *store;
  X509 *cert = NULL;
  BIO *bio;
  char *mypem = parm;
  /* get a BIO */
  bio = BIO_new_mem_buf(mypem, -1);
  /* use it to read the PEM formatted certificate from memory into an
   * X509 structure that SSL can use
   */
  PEM_read_bio_X509(bio, &cert, 0, NULL);
  if(!cert)
    printf("PEM_read_bio_X509 failed...\n");

  /* get a pointer to the X509 certificate store (which may be empty) */
  store = SSL_CTX_get_cert_store((SSL_CTX *)sslctx);

  /* add our certificate to this store */
  if(X509_STORE_add_cert(store, cert) == 0)
    printf("error adding certificate\n");

  /* decrease reference counts */
  X509_free(cert);
  BIO_free(bio);

  /* all set to go */
  return CURLE_OK;
}

int main(void)
{
  CURL *ch;
  CURLcode rv;
  char *mypem = /* example CA cert PEM - shortened */
    "-----BEGIN CERTIFICATE-----\n"
    "MIIHPTCCBSWgAwIBAgIBADANBgkqhkiG9w0BAQQFADB5MRAwDgYDVQQKEwdSb290\n"
    "IENBMR4wHAYDVQQLExVodHRwOi8vd3d3LmNhY2VydC5vcmcxIjAgBgNVBAMTGUNB\n"
    "IENlcnQgU2lnbmluZyBBdXRob3JpdHkxITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRA\n"
    "Y2FjZXJ0Lm9yZzAeFw0wMzAzMzAxMjI5NDlaFw0zMzAzMjkxMjI5NDlaMHkxEDAO\n"
    "GCSNe9FINSkYQKyTYOGWhlC0elnYjyELn8+CkcY7v2vcB5G5l1YjqrZslMZIBjzk\n"
    "zk6q5PYvCdxTby78dOs6Y5nCpqyJvKeyRKANihDjbPIky/qbn3BHLt4Ui9SyIAmW\n"
    "omTxJBzcoTWcFbLUvFUufQb1nA5V9FrWk9p2rSVzTMVD\n"
    "-----END CERTIFICATE-----\n";

  curl_global_init(CURL_GLOBAL_ALL);
  ch = curl_easy_init();

  curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(ch, CURLOPT_URL, "https://www.example.com/");

  curl_easy_setopt(ch, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
  curl_easy_setopt(ch, CURLOPT_SSL_CTX_DATA, mypem);
  rv = curl_easy_perform(ch);
  if(!rv)
    printf("*** transfer succeeded ***\n");
  else
    printf("*** transfer failed ***\n");

  curl_easy_cleanup(ch);
  curl_global_cleanup();
  return rv;
}
~~~

# AVAILABILITY

Added in 7.11.0 for OpenSSL, in 7.42.0 for wolfSSL, in 7.54.0 for mbedTLS,
in 7.83.0 in BearSSL. Other SSL backends are not supported.

# RETURN VALUE

CURLE_OK if supported; or an error such as:

CURLE_NOT_BUILT_IN - Not supported by the SSL backend

CURLE_UNKNOWN_OPTION
