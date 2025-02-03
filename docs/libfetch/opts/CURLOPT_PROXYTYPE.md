---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYTYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYPORT (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

FETCHOPT_PROXYTYPE - proxy protocol type

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYTYPE, long type);
~~~

# DESCRIPTION

Pass one of the values below to set the type of the proxy.

## FETCHPROXY_HTTP

HTTP Proxy. Default.

## FETCHPROXY_HTTPS

HTTPS Proxy using HTTP/1. (Added in 7.52.0 for OpenSSL and GnuTLS. Since
7.87.0, it also works for BearSSL, mbedTLS, Rustls, Schannel, Secure Transport
and wolfSSL.)

## FETCHPROXY_HTTPS2

HTTPS Proxy and attempt to speak HTTP/2 over it. (Added in 8.1.0)

## FETCHPROXY_HTTP_1_0

HTTP 1.0 Proxy. This is similar to FETCHPROXY_HTTP except it uses HTTP/1.0 for
any CONNECT tunneling. It does not change the HTTP version of the actual HTTP
requests, controlled by FETCHOPT_HTTP_VERSION(3).

## FETCHPROXY_SOCKS4

SOCKS4 Proxy.

## FETCHPROXY_SOCKS4A

SOCKS4a Proxy. Proxy resolves URL hostname.

## FETCHPROXY_SOCKS5

SOCKS5 Proxy.

## FETCHPROXY_SOCKS5_HOSTNAME

SOCKS5 Proxy. Proxy resolves URL hostname.

##

Often it is more convenient to specify the proxy type with the scheme part of
the FETCHOPT_PROXY(3) string.

# DEFAULT

FETCHPROXY_HTTP

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "local.example.com:1080");
    /* set the proxy type */
    fetch_easy_setopt(fetch, FETCHOPT_PROXYTYPE, FETCHPROXY_SOCKS5);
    ret = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
