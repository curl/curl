---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLKEY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLCERT (3)
  - FETCHOPT_PROXY_SSLKEYTYPE (3)
  - FETCHOPT_SSLCERT (3)
  - FETCHOPT_SSLKEY (3)
  - FETCHOPT_SSLKEYTYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSLKEY - private key file for HTTPS proxy client cert

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLKEY, char *keyfile);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the filename of your private key used for connecting to the HTTPS proxy. The
default format is "PEM" and can be changed with
FETCHOPT_PROXY_SSLKEYTYPE(3).

(Windows, iOS and macOS) This option is ignored by Secure Transport and
Schannel SSL backends because they expect the private key to be already
present in the key chain or PKCS#12 file containing the certificate.

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
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://proxy");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLCERT, "client.pem");
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
