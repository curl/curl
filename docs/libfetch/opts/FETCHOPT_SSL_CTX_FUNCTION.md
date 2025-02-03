---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_CTX_FUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CA_CACHE_TIMEOUT (3)
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_CAINFO_BLOB (3)
  - FETCHOPT_SSL_CTX_DATA (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
  - mbedTLS
  - BearSSL
Added-in: 7.10.6
---

# NAME

FETCHOPT_SSL_CTX_FUNCTION - SSL context callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode ssl_ctx_callback(FETCH *fetch, void *ssl_ctx, void *clientp);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_CTX_FUNCTION,
                          ssl_ctx_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch just before the initialization
of an SSL connection after having processed all other SSL related options to
give a last chance to an application to modify the behavior of the SSL
initialization. The *ssl_ctx* parameter is a pointer to the SSL library's
*SSL_CTX* for OpenSSL or wolfSSL, a pointer to *mbedtls_ssl_config* for
mbedTLS or a pointer to *br_ssl_client_context* for BearSSL. If an error is
returned from the callback no attempt to establish a connection is made and
the perform operation returns the callback's error code. Set the *clientp*
argument passed in to this callback with the FETCHOPT_SSL_CTX_DATA(3) option.

This function gets called for all new connections made to a server, during the
SSL negotiation. While *ssl_ctx* points to a newly initialized object each
time, the pointer may still be the same as in a prior call.

To use this callback, a non-trivial amount of knowledge of your SSL library is
necessary. For example, you can use this function to call library-specific
callbacks to add additional validation code for certificates, and even to
change the actual URI of an HTTPS request.

For OpenSSL, asynchronous certificate verification via *SSL_set_retry_verify*
is supported. (Added in 8.3.0)

The FETCHOPT_SSL_CTX_FUNCTION(3) callback allows the application to reach in
and modify SSL details in the connection without libfetch itself knowing
anything about it, which then subsequently can lead to libfetch unknowingly
reusing SSL connections with different properties. To remedy this you may set
FETCHOPT_FORBID_REUSE(3) from the callback function.

If you are using DNS-over-HTTPS (DoH) via FETCHOPT_DOH_URL(3) then this
callback is also called for those transfers and the fetch handle is set to an
internal handle. **This behavior is subject to change.** We recommend setting
FETCHOPT_PRIVATE(3) on your fetch handle so you can identify it correctly in the
context callback. If you have a reason to modify DoH SSL context please let us
know on the fetch-library mailing list because we are considering removing this
capability.

libfetch does not guarantee the lifetime of the passed in object once this
callback function has returned. Your application must not assume that it can
keep using the SSL context or data derived from it once this function is
completed.

For libfetch builds using TLS backends that support CA caching and
FETCHOPT_CA_CACHE_TIMEOUT(3) is not set to zero, multiple calls to this
callback may be done with the same CA store in memory.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
/* OpenSSL specific */

#include <openssl/ssl.h>
#include <fetch/fetch.h>
#include <stdio.h>

static FETCHcode sslctx_function(FETCH *fetch, void *sslctx, void *parm)
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
  return FETCHE_OK;
}

int main(void)
{
  FETCH *ch;
  FETCHcode rv;
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

  fetch_global_init(FETCH_GLOBAL_ALL);
  ch = fetch_easy_init();

  fetch_easy_setopt(ch, FETCHOPT_SSLCERTTYPE, "PEM");
  fetch_easy_setopt(ch, FETCHOPT_SSL_VERIFYPEER, 1L);
  fetch_easy_setopt(ch, FETCHOPT_URL, "https://www.example.com/");

  fetch_easy_setopt(ch, FETCHOPT_SSL_CTX_FUNCTION, *sslctx_function);
  fetch_easy_setopt(ch, FETCHOPT_SSL_CTX_DATA, mypem);
  rv = fetch_easy_perform(ch);
  if(!rv)
    printf("*** transfer succeeded ***\n");
  else
    printf("*** transfer failed ***\n");

  fetch_easy_cleanup(ch);
  fetch_global_cleanup();
  return rv;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK if supported; or an error such as:

FETCHE_NOT_BUILT_IN - Not supported by the SSL backend
