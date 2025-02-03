---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_TLSAUTH_USERNAME
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY_TLSAUTH_PASSWORD (3)
  - FETCHOPT_PROXY_TLSAUTH_TYPE (3)
  - FETCHOPT_TLSAUTH_PASSWORD (3)
  - FETCHOPT_TLSAUTH_TYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_TLSAUTH_USERNAME - username to use for proxy TLS authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_TLSAUTH_USERNAME,
                          char *user);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
username to use for the HTTPS proxy TLS authentication method specified with
the FETCHOPT_PROXY_TLSAUTH_TYPE(3) option. Requires that the
FETCHOPT_PROXY_TLSAUTH_PASSWORD(3) option also be set.

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
