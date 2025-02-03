---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DOH_URL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DNS_CACHE_TIMEOUT (3)
  - FETCHOPT_RESOLVE (3)
  - FETCHOPT_VERBOSE (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

FETCHOPT_DOH_URL - provide the DNS-over-HTTPS URL

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DOH_URL, char *URL);
~~~

# DESCRIPTION

Pass in a pointer to a *URL* for the DoH server to use for name resolving. The
parameter should be a char pointer to a null-terminated string which must be a
valid and correct HTTPS URL.

libfetch does not validate the syntax or use this variable until the transfer
is issued. Even if you set a crazy value here, fetch_easy_setopt(3) still
returns *FETCHE_OK*.

fetch sends POST requests to the given DNS-over-HTTPS URL.

To find the DoH server itself, which might be specified using a name, libfetch
uses the default name lookup function. You can bootstrap that by providing the
address for the DoH server with FETCHOPT_RESOLVE(3).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# INHERIT OPTIONS

DoH lookups use SSL and some SSL settings from your transfer are inherited,
like FETCHOPT_SSL_CTX_FUNCTION(3).

The hostname and peer certificate verification settings are not inherited but
can be controlled separately via FETCHOPT_DOH_SSL_VERIFYHOST(3) and
FETCHOPT_DOH_SSL_VERIFYPEER(3).

A set FETCHOPT_OPENSOCKETFUNCTION(3) callback is not inherited.

# KNOWN BUGS

Even when DoH is set to be used with this option, there are still some name
resolves that are performed without it, using the default name resolver
mechanism. This includes name resolves done for FETCHOPT_INTERFACE(3),
FETCHOPT_FTPPORT(3), a proxy type set to **FETCHPROXY_SOCKS4** or
**FETCHPROXY_SOCKS5** and probably some more.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_DOH_URL, "https://dns.example.com");
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).

Note that fetch_easy_setopt(3) does immediately parse the given string so when
given a bad DoH URL, libfetch might not detect the problem until it later tries
to resolve a name with it.
