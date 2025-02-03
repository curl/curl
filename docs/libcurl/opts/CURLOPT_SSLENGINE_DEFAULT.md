---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLENGINE_DEFAULT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSLCERT (3)
  - FETCHOPT_SSLENGINE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.9.3
---

# NAME

FETCHOPT_SSLENGINE_DEFAULT - make SSL engine default

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLENGINE_DEFAULT, long val);
~~~

# DESCRIPTION

Pass a long set to 1 to make the already specified crypto engine the default
for (asymmetric) crypto operations.

This option has no effect unless set after FETCHOPT_SSLENGINE(3).

# DEFAULT

None

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
    fetch_easy_setopt(fetch, FETCHOPT_SSLENGINE_DEFAULT, 1L);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK - Engine set as default.

FETCHE_SSL_ENGINE_SETFAILED - Engine could not be set as default.

FETCHE_NOT_BUILT_IN - Option not built in, OpenSSL is not the SSL backend.

FETCHE_UNKNOWN_OPTION - Option not recognized.

FETCHE_OUT_OF_MEMORY - Insufficient heap space.
