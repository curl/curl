---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSL_CIPHER_LIST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLVERSION (3)
  - FETCHOPT_PROXY_TLS13_CIPHERS (3)
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_SSL_CIPHER_LIST (3)
  - FETCHOPT_TLS13_CIPHERS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - BearSSL
  - Schannel
  - Secure Transport
  - wolfSSL
  - mbedTLS
  - rustls
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSL_CIPHER_LIST - ciphers to use for HTTPS proxy

# SYNOPSIS

```c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSL_CIPHER_LIST,
                          char *list);
```

# DESCRIPTION

Pass a char pointer, pointing to a null-terminated string holding the list of
cipher suites to use for the TLS 1.2 (1.1, 1.0) connection to the HTTPS proxy.
The list must be syntactically correct, it consists of one or more cipher suite
strings separated by colons.

For setting TLS 1.3 ciphers see FETCHOPT_PROXY_TLS13_CIPHERS(3).

A valid example of a cipher list is:

```
"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
```

For Schannel, you can use this option to set algorithms but not specific
cipher suites. Refer to the ciphers lists document for algorithms.

Find more details about cipher lists on this URL:

https://fetch.se/docs/ssl-ciphers.html

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL, use internal built-in list.

# %PROTOCOLS%

# EXAMPLE

```c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "https://localhost");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSL_CIPHER_LIST,
                     "ECDHE-ECDSA-CHACHA20-POLY1305:"
                     "ECDHE-RSA-CHACHA20-POLY1305");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
```

# HISTORY

OpenSSL support added in 7.52.0.
wolfSSL, Schannel, Secure Transport, and BearSSL support added in 7.87.0
mbedTLS support added in 8.8.0.
Rustls support added in 8.10.0.

Since fetch 8.10.0 returns FETCHE_NOT_BUILT_IN when not supported.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
