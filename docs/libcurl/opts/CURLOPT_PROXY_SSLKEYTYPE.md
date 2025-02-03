---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLKEYTYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLCERT (3)
  - FETCHOPT_PROXY_SSLKEY (3)
  - FETCHOPT_SSLKEYTYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - BearSSL
  - wolfSSL
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSLKEYTYPE - type of the proxy private key file

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLKEYTYPE, char *type);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a pointer to a null-terminated string as parameter. The string should be
the format of your private key. Supported formats are "PEM", "DER", "ENG" and
"PROV" (the latter added in fetch 8.12.0).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSLKEYTYPE, "PEM");
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
