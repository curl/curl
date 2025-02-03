---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DNS_INTERFACE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DNS_LOCAL_IP4 (3)
  - FETCHOPT_DNS_LOCAL_IP6 (3)
  - FETCHOPT_DNS_SERVERS (3)
  - FETCHOPT_INTERFACE (3)
Protocol:
  - All
Added-in: 7.33.0
---

# NAME

FETCHOPT_DNS_INTERFACE - interface to speak DNS over

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DNS_INTERFACE, char *ifname);
~~~

# DESCRIPTION

Pass a char pointer as parameter. Set the name of the network interface that
the DNS resolver should bind to. This must be an interface name (not an
address). Set this option to NULL to use the default setting (do not bind to a
specific interface).

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
    fetch_easy_setopt(fetch, FETCHOPT_DNS_INTERFACE, "eth0");
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
