---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CA_CACHE_TIMEOUT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CAINFO (3)
  - FETCHOPT_CAINFO_BLOB (3)
  - FETCHOPT_CAPATH (3)
  - FETCHOPT_SSL_VERIFYHOST (3)
  - FETCHOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - GnuTLS
  - OpenSSL
  - Schannel
  - wolfSSL
Added-in: 7.87.0
---

# NAME

FETCHOPT_CA_CACHE_TIMEOUT - life-time for cached certificate stores

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CA_CACHE_TIMEOUT, long age);
~~~

# DESCRIPTION

Pass a long, this sets the timeout in seconds. This tells libfetch the maximum
time any cached CA certificate store it has in memory may be kept and reused
for new connections. Once the timeout has expired, a subsequent fetch
requiring a CA certificate has to reload it.

Building a CA certificate store from a FETCHOPT_CAINFO(3) file is a slow
operation so fetch may cache the generated certificate store internally to
speed up future connections.

Set the timeout to zero to completely disable caching, or set to -1 to retain
the cached store remain forever. By default, libfetch caches this info for 24
hours.

# DEFAULT

86400 (24 hours)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* only reuse certificate stores for a short time */
    fetch_easy_setopt(fetch, FETCHOPT_CA_CACHE_TIMEOUT, 60L);

    res = fetch_easy_perform(fetch);

    /* in this second request, the cache is not used if more than
       sixty seconds passed since the previous connection */
    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option is supported by OpenSSL and its forks (since 7.87.0), Schannel
(since 8.5.0), wolfSSL (since 8.9.0) and GnuTLS (since 8.9.0).

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
