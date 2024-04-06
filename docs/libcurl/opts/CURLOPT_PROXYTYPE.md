---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYTYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYPORT (3)
Protocol:
  - All
---

# NAME

CURLOPT_PROXYTYPE - proxy protocol type

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYTYPE, long type);
~~~

# DESCRIPTION

Pass one of the values below to set the type of the proxy.

## CURLPROXY_HTTP

HTTP Proxy. Default.

## CURLPROXY_HTTPS

HTTPS Proxy using HTTP/1. (Added in 7.52.0 for OpenSSL and GnuTLS. Since
7.87.0, it also works for BearSSL, mbedTLS, rustls, Schannel, Secure Transport
and wolfSSL.)

## CURLPROXY_HTTPS2

HTTPS Proxy and attempt to speak HTTP/2 over it. (Added in 8.1.0)

## CURLPROXY_HTTP_1_0

HTTP 1.0 Proxy. This is similar to CURLPROXY_HTTP except it uses HTTP/1.0 for
any CONNECT tunneling. It does not change the HTTP version of the actual HTTP
requests, controlled by CURLOPT_HTTP_VERSION(3).

## CURLPROXY_SOCKS4

SOCKS4 Proxy.

## CURLPROXY_SOCKS4A

SOCKS4a Proxy. Proxy resolves URL hostname.

## CURLPROXY_SOCKS5

SOCKS5 Proxy.

## CURLPROXY_SOCKS5_HOSTNAME

SOCKS5 Proxy. Proxy resolves URL hostname.

Often it is more convenient to specify the proxy type with the scheme part of
the CURLOPT_PROXY(3) string.

# DEFAULT

CURLPROXY_HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "local.example.com:1080");
    /* set the proxy type */
    curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
