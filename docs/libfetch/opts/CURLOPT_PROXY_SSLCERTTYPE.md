---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLCERTTYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLCERT (3)
  - FETCHOPT_PROXY_SSLKEY (3)
  - FETCHOPT_SSLCERTTYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - Schannel
  - Secure Transport
  - wolfSSL
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSLCERTTYPE - type of the proxy client SSL certificate

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLCERTTYPE, char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the format of your client certificate used when connecting to an HTTPS proxy.

Supported formats are "PEM" and "DER", except with Secure Transport or
Schannel. OpenSSL (versions 0.9.3 and later), Secure Transport (on iOS 5 or
later, or macOS 10.7 or later) and Schannel support "P12" for PKCS#12-encoded
files.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

"PEM"

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERT, "client.pem");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERTTYPE, "PEM");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLKEY, "key.pem");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_KEYPASSWD, "s3cret");
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
