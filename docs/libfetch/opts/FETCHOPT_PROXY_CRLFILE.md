---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_CRLFILE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
  - mbedTLS
  - OpenSSL
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_CRLFILE - HTTPS proxy Certificate Revocation List file

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_CRLFILE, char *file);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a char pointer to a null-terminated string naming a *file* with the
concatenation of CRL (in PEM format) to use in the certificate validation that
occurs during the SSL exchange.

When fetch is built to use GnuTLS, there is no way to influence the use of CRL
passed to help in the verification process. When libfetch is built with OpenSSL
support, X509_V_FLAG_CRL_CHECK and X509_V_FLAG_CRL_CHECK_ALL are both set,
requiring CRL check against all the elements of the certificate chain if a CRL
file is passed.

This option makes sense only when used in combination with the
FETCHOPT_PROXY_SSL_VERIFYPEER(3) option.

A specific error code (*FETCHE_SSL_CRL_BADFILE*) is defined with the option. It
is returned when the SSL exchange fails because the CRL file cannot be loaded.
A failure in certificate verification due to a revocation information found in
the CRL does not trigger this specific error.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://localhost:80");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_CRLFILE, "/etc/certs/crl.pem");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
