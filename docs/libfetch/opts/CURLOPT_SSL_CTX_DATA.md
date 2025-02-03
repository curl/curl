---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_CTX_DATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_SSL_CTX_FUNCTION (3)
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

FETCHOPT_SSL_CTX_DATA - pointer passed to SSL context callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_CTX_DATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the ssl context callback set by the option
FETCHOPT_SSL_CTX_FUNCTION(3), this is the pointer you get as third
parameter.

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

# HISTORY

Added in 7.11.0 for OpenSSL, in 7.42.0 for wolfSSL, in 7.54.0 for mbedTLS,
in 7.83.0 in BearSSL.

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK if supported; or an error such as:

FETCHE_NOT_BUILT_IN - Not supported by the SSL backend

FETCHE_UNKNOWN_OPTION
