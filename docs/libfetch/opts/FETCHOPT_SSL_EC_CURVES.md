---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_EC_CURVES
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSL_CIPHER_LIST (3)
  - FETCHOPT_SSL_OPTIONS (3)
  - FETCHOPT_TLS13_CIPHERS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
Added-in: 7.73.0
---

# NAME

FETCHOPT_SSL_EC_CURVES - key exchange curves

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_EC_CURVES, char *list);
~~~

# DESCRIPTION

Pass a string as parameter with a colon delimited list of Elliptic curve (EC)
algorithms. This option defines the client's key exchange algorithms in the
SSL handshake (if the SSL backend libfetch is built to use supports it).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore back to internal default.

# DEFAULT

"", embedded in SSL backend

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SSL_EC_CURVES, "X25519:P-521");
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
