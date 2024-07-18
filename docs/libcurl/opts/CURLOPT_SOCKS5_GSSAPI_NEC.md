---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SOCKS5_GSSAPI_NEC
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXY_SERVICE_NAME (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

CURLOPT_SOCKS5_GSSAPI_NEC - SOCKS proxy GSSAPI negotiation protection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SOCKS5_GSSAPI_NEC, long nec);
~~~

# DESCRIPTION

Pass a long set to 1 to enable or 0 to disable. As part of the GSSAPI
negotiation a protection mode is negotiated. The RFC 1961 says in section
4.3/4.4 it should be protected, but the NEC reference implementation does not.
If enabled, this option allows the unprotected exchange of the protection mode
negotiation.

# DEFAULT

?

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://proxy");
    curl_easy_setopt(curl, CURLOPT_SOCKS5_GSSAPI_NEC, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
