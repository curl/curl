---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSLVERSION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_IPRESOLVE (3)
  - FETCHOPT_PROXY_SSLVERSION (3)
  - FETCHOPT_USE_SSL (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_SSLVERSION - preferred TLS/SSL version

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSLVERSION, long version);
~~~

# DESCRIPTION

Pass a long as parameter to control which version range of SSL/TLS versions to
use.

The SSL and TLS versions have typically developed from the most insecure
version to be more and more secure in this order through history: SSL v2,
SSLv3, TLS v1.0, TLS v1.1, TLS v1.2 and the most recent TLS v1.3.

Use one of the available defines for this purpose. The available options are:

## FETCH_SSLVERSION_DEFAULT

The default acceptable version range. The minimum acceptable version is by
default TLS v1.0 since 7.39.0 (unless the TLS library has a stricter rule).

## FETCH_SSLVERSION_TLSv1

TLS v1.0 or later

## FETCH_SSLVERSION_SSLv2

SSL v2 - refused

## FETCH_SSLVERSION_SSLv3

SSL v3 - refused

## FETCH_SSLVERSION_TLSv1_0

TLS v1.0 or later (Added in 7.34.0)

## FETCH_SSLVERSION_TLSv1_1

TLS v1.1 or later (Added in 7.34.0)

## FETCH_SSLVERSION_TLSv1_2

TLS v1.2 or later (Added in 7.34.0)

## FETCH_SSLVERSION_TLSv1_3

TLS v1.3 or later (Added in 7.52.0)

##

The maximum TLS version can be set by using *one* of the
FETCH_SSLVERSION_MAX_ macros below. It is also possible to OR *one* of the
FETCH_SSLVERSION_ macros with *one* of the FETCH_SSLVERSION_MAX_ macros.

## FETCH_SSLVERSION_MAX_DEFAULT

The flag defines the maximum supported TLS version by libfetch, or the default
value from the SSL library is used. libfetch uses a sensible default maximum,
which was TLS v1.2 up to before 7.61.0 and is TLS v1.3 since then - assuming
the TLS library support it. (Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_0

The flag defines maximum supported TLS version as TLS v1.0.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_1

The flag defines maximum supported TLS version as TLS v1.1.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_2

The flag defines maximum supported TLS version as TLS v1.2.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_3

The flag defines maximum supported TLS version as TLS v1.3.
(Added in 7.54.0)

##

In versions of fetch prior to 7.54 the FETCH_SSLVERSION_TLS options were
documented to allow *only* the specified TLS version, but behavior was
inconsistent depending on the TLS library.

# DEFAULT

FETCH_SSLVERSION_DEFAULT

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* ask libfetch to use TLS version 1.0 or later */
    fetch_easy_setopt(fetch, FETCHOPT_SSLVERSION, (long)FETCH_SSLVERSION_TLSv1);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

SSLv2 is disabled by default since 7.18.1. Other SSL versions availability may
vary depending on which backend libfetch has been built to use.

SSLv3 is disabled by default since 7.39.0.

SSLv2 and SSLv3 are refused completely since fetch 7.77.0

Since 8.10.0 wolfSSL is fully supported. Before 8.10.0 the MAX macros were not
supported with wolfSSL and the other macros did not set a minimum, but
restricted the TLS version to only the specified one.

Rustls support added in 8.10.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
