---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXYPORT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PRIMARY_PORT (3)
  - CURLOPT_PORT (3)
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.1
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
specified in the proxy string CURLOPT_PROXY(3) or uses 443 for https proxies
and 1080 for all others as default.

Disabling this option, setting it to zero, makes it not specified which makes
libcurl use the default proxy port number or the port number specified in the
proxy URL string.

While this accepts a 'long', the port number is 16 bit so it cannot be larger
than 65535.

# DEFAULT

0

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
