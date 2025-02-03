---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DNS_SERVERS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DNS_CACHE_TIMEOUT (3)
  - FETCHOPT_DNS_LOCAL_IP4 (3)
  - FETCHOPT_DNS_LOCAL_IP6 (3)
Protocol:
  - All
Added-in: 7.24.0
---

# NAME

FETCHOPT_DNS_SERVERS - DNS servers to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DNS_SERVERS, char *servers);
~~~

# DESCRIPTION

Pass a char pointer that is the list of DNS servers to be used instead of the
system default. The format of the dns servers option is:

    host[:port][,host[:port]]...

For example:

    192.168.1.100,192.168.1.101,3.4.5.6

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_DNS_SERVERS,
                     "192.168.1.100:53,192.168.1.101");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# NOTES

This option requires that libfetch was built with a resolver backend that
supports this operation. The c-ares backend is the only such one.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
