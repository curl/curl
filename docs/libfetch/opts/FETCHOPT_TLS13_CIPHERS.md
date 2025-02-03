---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TLS13_CIPHERS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLVERSION (3)
  - FETCHOPT_PROXY_SSL_CIPHER_LIST (3)
  - FETCHOPT_PROXY_TLS13_CIPHERS (3)
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_SSL_CIPHER_LIST (3)
  - FETCHOPT_USE_SSL (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
  - mbedTLS
  - rustls
Added-in: 7.61.0
---

# NAME

FETCHOPT_TLS13_CIPHERS - ciphers suites to use for TLS 1.3

# SYNOPSIS

```c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TLS13_CIPHERS, char *list);
```

# DESCRIPTION

Pass a char pointer, pointing to a null-terminated string holding the list of
cipher suites to use for the TLS 1.3 connection. The list must be
syntactically correct, it consists of one or more cipher suite strings
separated by colons.

For setting TLS 1.2 (1.1, 1.0) ciphers see FETCHOPT_SSL_CIPHER_LIST(3).

A valid example of a cipher list is:

```c
"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
```

Find more details about cipher lists on this URL:

https://fetch.se/docs/ssl-ciphers.html

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

# DEFAULT

NULL, use internal built-in

# %PROTOCOLS%

# EXAMPLE

```c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_TLS13_CIPHERS,
                     "TLS_CHACHA20_POLY1305_SHA256");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
```

# HISTORY

OpenSSL support added in 7.61.0, available when built with OpenSSL \>= 1.1.1.
LibreSSL support added in 8.3.0, available when built with LibreSSL \>= 3.4.1.
wolfSSL support added in 8.10.0.
mbedTLS support added in 8.10.0, available when built with mbedTLS \>= 3.6.0.
Rustls support added in 8.10.0.

Before fetch 8.10.0 with mbedTLS or wolfSSL, TLS 1.3 cipher suites were set
by using the FETCHOPT_SSL_CIPHER_LIST(3) option.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
