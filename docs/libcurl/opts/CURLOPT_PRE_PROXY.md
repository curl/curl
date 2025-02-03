---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PRE_PROXY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPROXYTUNNEL (3)
  - FETCHOPT_PROXY (3)
Protocol:
  - All
Added-in: 7.52.0
---

# NAME

FETCHOPT_PRE_PROXY - pre-proxy host to use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PRE_PROXY, char *preproxy);
~~~

# DESCRIPTION

Set the *preproxy* to use for the upcoming request. The parameter should be a
char * to a null-terminated string holding the hostname or dotted numerical IP
address. A numerical IPv6 address must be written within [brackets].

To specify port number in this string, append :[port] to the end of the host
name. The proxy's port number may optionally be specified with the separate
option FETCHOPT_PROXYPORT(3). If not specified, libfetch defaults to using
port 1080 for proxies.

A pre proxy is a SOCKS proxy that fetch connects to before it connects to the
HTTP(S) proxy specified in the FETCHOPT_PROXY(3) option. The pre proxy
can only be a SOCKS proxy.

The pre proxy string should be prefixed with [scheme]:// to specify which kind
of socks is used. Use socks4://, socks4a://, socks5:// or socks5h:// (the last
one to enable socks5 and asking the proxy to do the resolving, also known as
*FETCHPROXY_SOCKS5_HOSTNAME* type) to request the specific SOCKS version to
be used. Otherwise SOCKS4 is used as default.

Setting the pre proxy string to "" (an empty string) explicitly disables the
use of a pre proxy.

When you set a hostname to use, do not assume that there is any particular
single port number used widely for proxies. Specify it.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/file.txt");
    fetch_easy_setopt(fetch, FETCHOPT_PRE_PROXY, "socks4://socks-proxy:1080");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://proxy:80");
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
