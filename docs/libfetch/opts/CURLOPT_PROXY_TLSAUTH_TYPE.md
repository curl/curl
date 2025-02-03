---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_TLSAUTH_TYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_TLSAUTH_PASSWORD (3)
  - FETCHOPT_PROXY_TLSAUTH_USERNAME (3)
  - FETCHOPT_TLSAUTH_PASSWORD (3)
  - FETCHOPT_TLSAUTH_USERNAME (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_TLSAUTH_TYPE - HTTPS proxy TLS authentication methods

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_TLSAUTH_TYPE,
                          char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the method of the TLS authentication used for the HTTPS connection. Supported
method is "SRP".

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

The application does not have to keep the string around after setting this
option.

## SRP

TLS-SRP authentication. Secure Remote Password authentication for TLS is
defined in RFC 5054 and provides mutual authentication if both sides have a
shared secret. To use TLS-SRP, you must also set the
FETCHOPT_PROXY_TLSAUTH_USERNAME(3) and FETCHOPT_PROXY_TLSAUTH_PASSWORD(3)
options.

# DEFAULT

blank

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
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_TLSAUTH_TYPE, "SRP");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_TLSAUTH_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_TLSAUTH_PASSWORD, "secret");
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
