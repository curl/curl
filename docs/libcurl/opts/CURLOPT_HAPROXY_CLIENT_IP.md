---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HAPROXY_CLIENT_IP
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_HAPROXYPROTOCOL (3)
  - FETCHOPT_PROXY (3)
Added-in: 8.2.0
---

# NAME

FETCHOPT_HAPROXY_CLIENT_IP - set HAProxy PROXY protocol client IP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HAPROXY_CLIENT_IP,
                          char *client_ip);
~~~

# DESCRIPTION

When this parameter is set to a valid IPv4 or IPv6 numerical address, the
library sends this address as client address in the HAProxy PROXY protocol v1
header at beginning of the connection.

This option is an alternative to FETCHOPT_HAPROXYPROTOCOL(3) as that one cannot
use a specified address.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, no HAProxy header is sent

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_HAPROXY_CLIENT_IP, "1.1.1.1");
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
