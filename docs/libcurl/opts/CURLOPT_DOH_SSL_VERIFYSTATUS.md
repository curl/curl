---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DOH_SSL_VERIFYSTATUS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DOH_SSL_VERIFYHOST (3)
  - FETCHOPT_DOH_SSL_VERIFYPEER (3)
  - FETCHOPT_SSL_VERIFYSTATUS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.76.0
---

# NAME

FETCHOPT_DOH_SSL_VERIFYSTATUS - verify the DoH SSL certificate's status

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DOH_SSL_VERIFYSTATUS,
                          long verify);
~~~

# DESCRIPTION

Pass a long as parameter set to 1 to enable or 0 to disable.

This option determines whether libfetch verifies the status of the DoH
(DNS-over-HTTPS) server cert using the "Certificate Status Request" TLS
extension (aka. OCSP stapling).

This option is the DoH equivalent of FETCHOPT_SSL_VERIFYSTATUS(3) and
only affects requests to the DoH server.

If this option is enabled and the server does not support the TLS extension,
the verification fails.

# DEFAULT

0

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

    /* Ask for OCSP stapling when verifying the DoH server */
    fetch_easy_setopt(fetch, FETCHOPT_DOH_SSL_VERIFYSTATUS, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
