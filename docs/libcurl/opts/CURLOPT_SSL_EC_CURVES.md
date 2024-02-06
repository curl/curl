---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_EC_CURVES
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_CIPHER_LIST (3)
  - CURLOPT_SSL_OPTIONS (3)
  - CURLOPT_TLS13_CIPHERS (3)
---

# NAME

CURLOPT_SSL_EC_CURVES - key exchange curves

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_EC_CURVES, char *alg_list);
~~~

# DESCRIPTION

Pass a string as parameter with a colon delimited list of (EC) algorithms. This
option defines the client's key exchange algorithms in the SSL handshake (if
the SSL backend libcurl is built to use supports it).

# DEFAULT

"", embedded in SSL backend

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSL_EC_CURVES, "X25519:P-521");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.73.0. Supported by the OpenSSL backend.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
