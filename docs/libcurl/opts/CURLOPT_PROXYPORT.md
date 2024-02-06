---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYPORT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PRIMARY_PORT (3)
  - CURLOPT_PORT (3)
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
---

# NAME

CURLOPT_PROXYPORT - port number the proxy listens on

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXYPORT, long port);
~~~

# DESCRIPTION

We discourage use of this option.

Pass a long with this option to set the proxy port to connect to unless it is
specified in the proxy string CURLOPT_PROXY(3) or uses 443 for https
proxies and 1080 for all others as default.

While this accepts a 'long', the port number is 16 bit so it cannot be larger
than 65535.

# DEFAULT

0, not specified which makes it use the default port

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_PROXY, "localhost");
    curl_easy_setopt(curl, CURLOPT_PROXYPORT, 8080L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
