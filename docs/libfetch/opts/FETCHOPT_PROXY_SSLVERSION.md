---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXY_SSLVERSION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_IPRESOLVE (3)
  - FETCHOPT_SSLVERSION (3)
  - FETCHOPT_USE_SSL (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.52.0
---

# NAME

FETCHOPT_PROXY_SSLVERSION - preferred HTTPS proxy TLS version

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXY_SSLVERSION,
                          long version);
~~~

# DESCRIPTION

Pass a long as parameter to control which version of SSL/TLS to attempt to use
when connecting to an HTTPS proxy.

Use one of the available defines for this purpose. The available options are:

## FETCH_SSLVERSION_DEFAULT

The default action. This attempts to figure out the remote SSL protocol
version.

## FETCH_SSLVERSION_TLSv1

TLSv1.x

## FETCH_SSLVERSION_TLSv1_0

TLSv1.0

## FETCH_SSLVERSION_TLSv1_1

TLSv1.1

## FETCH_SSLVERSION_TLSv1_2

TLSv1.2

## FETCH_SSLVERSION_TLSv1_3

TLSv1.3

##

The maximum TLS version can be set by using *one* of the FETCH_SSLVERSION_MAX_
macros below. It is also possible to OR *one* of the FETCH_SSLVERSION_ macros
with *one* of the FETCH_SSLVERSION_MAX_ macros. The MAX macros are not
supported for wolfSSL.

## FETCH_SSLVERSION_MAX_DEFAULT

The flag defines the maximum supported TLS version as TLSv1.2, or the default
value from the SSL library.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_0

The flag defines maximum supported TLS version as TLSv1.0.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_1

The flag defines maximum supported TLS version as TLSv1.1.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_2

The flag defines maximum supported TLS version as TLSv1.2.
(Added in 7.54.0)

## FETCH_SSLVERSION_MAX_TLSv1_3

The flag defines maximum supported TLS version as TLSv1.3.
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
    fetch_easy_setopt(fetch, FETCHOPT_SSLVERSION, FETCH_SSLVERSION_TLSv1);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
