---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TLSAUTH_TYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TLSAUTH_PASSWORD (3)
  - FETCHOPT_TLSAUTH_USERNAME (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.21.4
---

# NAME

FETCHOPT_TLSAUTH_TYPE - TLS authentication methods

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TLSAUTH_TYPE, char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the method of the TLS authentication. Supported method is "SRP".

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

The application does not have to keep the string around after setting this
option.

## SRP

TLS-SRP authentication. Secure Remote Password authentication for TLS is
defined in RFC 5054 and provides mutual authentication if both sides have a
shared secret. To use TLS-SRP, you must also set the
FETCHOPT_TLSAUTH_USERNAME(3) and FETCHOPT_TLSAUTH_PASSWORD(3) options.

TLS SRP does not work with TLS 1.3.

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
    fetch_easy_setopt(fetch, FETCHOPT_TLSAUTH_TYPE, "SRP");
    fetch_easy_setopt(fetch, FETCHOPT_TLSAUTH_USERNAME, "user");
    fetch_easy_setopt(fetch, FETCHOPT_TLSAUTH_PASSWORD, "secret");
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
