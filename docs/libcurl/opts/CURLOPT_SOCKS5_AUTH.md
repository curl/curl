---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SOCKS5_AUTH
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLOPT_SOCKS5_AUTH - methods for SOCKS5 proxy authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SOCKS5_AUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libcurl which
authentication method(s) are allowed for SOCKS5 proxy authentication. The only
supported flags are *CURLAUTH_BASIC*, which allows username/password
authentication, *CURLAUTH_GSSAPI*, which allows GSS-API authentication, and
*CURLAUTH_NONE*, which allows no authentication. Set the actual username and
password with the CURLOPT_PROXYUSERPWD(3) option.

# DEFAULT

CURLAUTH_BASIC|CURLAUTH_GSSAPI

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* request to use a SOCKS5 proxy */
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://user:pass@myproxy.com");

    /* enable username/password authentication only */
    curl_easy_setopt(curl, CURLOPT_SOCKS5_AUTH, (long)CURLAUTH_BASIC);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_NOT_BUILT_IN if the bitmask contains unsupported flags.
