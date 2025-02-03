---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_IPRESOLVE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_RESOLVE (3)
  - FETCHOPT_SSLVERSION (3)
Protocol:
  - All
Added-in: 7.10.8
---

# NAME

FETCHOPT_IPRESOLVE - IP protocol version to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_IPRESOLVE, long resolve);
~~~

# DESCRIPTION

Allows an application to select what kind of IP addresses to use when
establishing a connection or choosing one from the connection pool. This is
interesting when using hostnames that resolve to more than one IP family.

If the URL provided for a transfer contains a numerical IP version as a host
name, this option does not override or prohibit libfetch from using that IP
version.

Available values for this option are:

## FETCH_IPRESOLVE_WHATEVER

Default, can use addresses of all IP versions that your system allows.

## FETCH_IPRESOLVE_V4

Uses only IPv4 addresses.

## FETCH_IPRESOLVE_V6

Uses only IPv6 addresses.

# DEFAULT

FETCH_IPRESOLVE_WHATEVER

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* of all addresses example.com resolves to, only IPv6 ones are used */
    fetch_easy_setopt(fetch, FETCHOPT_IPRESOLVE, FETCH_IPRESOLVE_V6);

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
