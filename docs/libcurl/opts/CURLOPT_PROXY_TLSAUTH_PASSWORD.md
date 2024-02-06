---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_TLSAUTH_PASSWORD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_TLSAUTH_TYPE (3)
  - CURLOPT_PROXY_TLSAUTH_USERNAME (3)
  - CURLOPT_TLSAUTH_TYPE (3)
  - CURLOPT_TLSAUTH_USERNAME (3)
---

# NAME

CURLOPT_PROXY_TLSAUTH_PASSWORD - password to use for proxy TLS authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_TLSAUTH_PASSWORD,
                          char *pwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
password to use for the TLS authentication method specified with the
CURLOPT_PROXY_TLSAUTH_TYPE(3) option. Requires that the
CURLOPT_PROXY_TLSAUTH_USERNAME(3) option also be set.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_TYPE, "SRP");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_PASSWORD, "secret");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.52.0, with the OpenSSL and GnuTLS backends only

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
