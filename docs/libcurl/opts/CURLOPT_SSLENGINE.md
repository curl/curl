---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLENGINE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SSL_ENGINES (3)
  - FETCHOPT_SSLENGINE_DEFAULT (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.9.3
---

# NAME

FETCHOPT_SSLENGINE - SSL engine identifier

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLENGINE, char *id);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used as the
identifier for the crypto engine you want to use for your private key.

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
    fetch_easy_setopt(fetch, FETCHOPT_SSLENGINE, "dynamic");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK - Engine found.

FETCHE_SSL_ENGINE_NOTFOUND - Engine not found, or OpenSSL was not built with
engine support.

FETCHE_SSL_ENGINE_INITFAILED - Engine found but initialization failed.

FETCHE_NOT_BUILT_IN - Option not built in, OpenSSL is not the SSL backend.

FETCHE_UNKNOWN_OPTION - Option not recognized.

FETCHE_OUT_OF_MEMORY - Insufficient heap space.
