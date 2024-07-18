---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SOCKS5_GSSAPI_SERVICE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

CURLOPT_SOCKS5_GSSAPI_SERVICE - SOCKS5 proxy authentication service name

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SOCKS5_GSSAPI_SERVICE,
                          char *name);
~~~

# DESCRIPTION

Deprecated since 7.49.0. Use CURLOPT_PROXY_SERVICE_NAME(3) instead.

Pass a char pointer as parameter to a string holding the *name* of the
service. The default service name for a SOCKS5 server is *rcmd*. This option
allows you to change it.

The application does not have to keep the string around after setting this
option.

# DEFAULT

See above

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
    curl_easy_setopt(curl, CURLOPT_SOCKS5_GSSAPI_SERVICE, "rcmd-special");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# DEPRECATED

Deprecated since 7.49.0

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
