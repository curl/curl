---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSL_VERIFYHOST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_PROXY_CAINFO (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSL_VERIFYHOST - verify the proxy certificate's name against host

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSL_VERIFYHOST,
                          long verify);
~~~

# DESCRIPTION

Pass a long set to 2L as asking fetch to *verify* in the HTTPS proxy's
certificate name fields against the proxy name.

This option determines whether libfetch verifies that the proxy cert contains
the correct name for the name it is known as.

When FETCHOPT_PROXY_SSL_VERIFYHOST(3) is 2, the proxy certificate must
indicate that the server is the proxy to which you meant to connect to, or the
connection fails.

fetch considers the proxy the intended one when the Common Name field or a
Subject Alternate Name field in the certificate matches the hostname in the
proxy string which you told fetch to use.

If *verify* value is set to 1:

In 7.28.0 and earlier: treated as a debug option of some sorts, not supported
anymore due to frequently leading to programmer mistakes.

From 7.28.1 to 7.65.3: setting it to 1 made fetch_easy_setopt(3) return
an error and leaving the flag untouched.

From 7.66.0: treats 1 and 2 the same.

When the *verify* value is 0L, the connection succeeds regardless of the
names used in the certificate. Use that ability with caution.

See also FETCHOPT_PROXY_SSL_VERIFYPEER(3) to verify the digital signature
of the proxy certificate.

# DEFAULT

2

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Set the default value: strict name check please */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY_SSL_VERIFYHOST, 2L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
