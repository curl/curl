---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DOH_SSL_VERIFYHOST
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DOH_SSL_VERIFYPEER (3)
  - FETCHOPT_PROXY_SSL_VERIFYHOST (3)
  - FETCHOPT_PROXY_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.76.0
---

# NAME

FETCHOPT_DOH_SSL_VERIFYHOST - verify the hostname in the DoH SSL certificate

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DOH_SSL_VERIFYHOST,
                          long verify);
~~~

# DESCRIPTION

Pass a long set to 2L as asking fetch to *verify* the DoH (DNS-over-HTTPS)
server's certificate name fields against the hostname.

This option is the DoH equivalent of FETCHOPT_SSL_VERIFYHOST(3) and
only affects requests to the DoH server.

When FETCHOPT_DOH_SSL_VERIFYHOST(3) is 2, the SSL certificate provided by
the DoH server must indicate that the server name is the same as the server
name to which you meant to connect to, or the connection fails.

fetch considers the DoH server the intended one when the Common Name field or a
Subject Alternate Name field in the certificate matches the hostname in the
DoH URL to which you told fetch to connect.

When the *verify* value is set to 1L it is treated the same as 2L. However
for consistency with the other *VERIFYHOST* options we suggest use 2 and
not 1.

When the *verify* value is set to 0L, the connection succeeds regardless of
the names used in the certificate. Use that ability with caution.

See also FETCHOPT_DOH_SSL_VERIFYPEER(3) to verify the digital signature
of the DoH server certificate.

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

    fetch_easy_setopt(fetch, FETCHOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");

    /* Disable host name verification of the DoH server */
    fetch_easy_setopt(fetch, FETCHOPT_DOH_SSL_VERIFYHOST, 0L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
