---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPPROXYUDPTUNNEL
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYPORT (3)
  - CURLOPT_PROXYTYPE (3)
  - CURLOPT_HTTPPROXYTUNNEL (3)
  - CURLOPT_HTTP_VERSION (3)
Added-in: 8.20.0
---

# NAME

CURLOPT_HTTPPROXYUDPTUNNEL - tunnel through HTTP proxy using CONNECT-UDP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPPROXYUDPTUNNEL, long udptunnel);
~~~

# DESCRIPTION

This feature is experimental and requires a build with HTTP/3 proxy support
enabled.

Set the **udptunnel** parameter to 1L to make libcurl tunnel operations
through an HTTP proxy (set with CURLOPT_PROXY(3)) using CONNECT-UDP.

UDP tunneling means that a CONNECT-UDP request is sent to the proxy,
asking it to establish a UDP relay to a remote host on a specific port
number. Once the tunnel is established, UDP datagrams are encapsulated
and forwarded through the proxy, allowing end-to-end communication with
the target server. Proxies may restrict which destinations or ports are
allowed for CONNECT-UDP.

Unlike traditional HTTP CONNECT tunneling, which is stream-oriented and
used for TCP, CONNECT-UDP supports connectionless protocols such as
QUIC, HTTP/3, or other UDP-based traffic.

When not using UDP tunneling, libcurl cannot use UDP-based protocols
through an HTTP proxy, as HTTP proxies do not support forwarding UDP
traffic. Enabling CONNECT-UDP makes this possible by relaying UDP
datagrams through the proxy.

CONNECT-UDP typically requires an HTTP/3-capable proxy and appropriate
support on both the client and proxy side.

This option is intentionally explicit. libcurl does not automatically
infer CONNECT-UDP from HTTP/3 settings because origin HTTP version
and proxy tunnel type are configured independently.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy.example.com");
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYUDPTUNNEL, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3ONLY);
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
