---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTPPROXYTUNNEL
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYPORT (3)
  - FETCHOPT_PROXYTYPE (3)
Added-in: 7.3
---

# NAME

FETCHOPT_HTTPPROXYTUNNEL - tunnel through HTTP proxy

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTPPROXYTUNNEL, long tunnel);
~~~

# DESCRIPTION

Set the **tunnel** parameter to 1L to make libfetch tunnel all operations
through the HTTP proxy (set with FETCHOPT_PROXY(3)). There is a big
difference between using a proxy and to tunnel through it.

Tunneling means that an HTTP CONNECT request is sent to the proxy, asking it
to connect to a remote host on a specific port number and then the traffic is
just passed through the proxy. Proxies tend to white-list specific port numbers
it allows CONNECT requests to and often only port 80 and 443 are allowed.

To suppress proxy CONNECT response headers from user callbacks use
FETCHOPT_SUPPRESS_CONNECT_HEADERS(3).

HTTP proxies can generally only speak HTTP (for obvious reasons), which makes
libfetch convert non-HTTP requests to HTTP when using an HTTP proxy without
this tunnel option set. For example, asking for an FTP URL and specifying an
HTTP proxy makes libfetch send an FTP URL in an HTTP GET request to the
proxy. By instead tunneling through the proxy, you avoid that conversion (that
rarely works through the proxy anyway).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://127.0.0.1:80");
    fetch_easy_setopt(fetch, FETCHOPT_HTTPPROXYTUNNEL, 1L);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
