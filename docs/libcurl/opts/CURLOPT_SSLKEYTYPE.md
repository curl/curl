---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLKEYTYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_SSLKEYTYPE (3)
  - FETCHOPT_SSLCERT (3)
  - FETCHOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - BearSSL
  - wolfSSL
Added-in: 7.9.3
---

# NAME

FETCHOPT_SSLKEYTYPE - type of the private key file

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLKEYTYPE, char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the format of your private key. Supported formats are "PEM", "DER", "ENG" and
"PROV".

The format "ENG" enables you to load the private key from a crypto engine. In
this case FETCHOPT_SSLKEY(3) is used as an identifier passed to the engine. You
have to set the crypto engine with FETCHOPT_SSLENGINE(3).

The format "PROV" enables you to load the private key from a crypto provider
(Added in 8.12.0). In this case FETCHOPT_SSLKEY(3) is used as an identifier
passed to the provider.

The "DER" format does not work with OpenSSL.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

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
    fetch_easy_setopt(fetch, FETCHOPT_SSLCERT, "client.pem");
    fetch_easy_setopt(fetch, FETCHOPT_SSLKEY, "key.pem");
    fetch_easy_setopt(fetch, FETCHOPT_SSLKEYTYPE, "PEM");
    fetch_easy_setopt(fetch, FETCHOPT_KEYPASSWD, "s3cret");
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
