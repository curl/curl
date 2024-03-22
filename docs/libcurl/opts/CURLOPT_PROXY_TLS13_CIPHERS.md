---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_TLS13_CIPHERS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLVERSION (3)
  - CURLOPT_PROXY_SSL_CIPHER_LIST (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_SSL_CIPHER_LIST (3)
  - CURLOPT_TLS13_CIPHERS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - rustls
  - Schannel
---

# NAME

CURLOPT_PROXY_TLS13_CIPHERS - ciphers suites for proxy TLS 1.3

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_TLS13_CIPHERS,
                          char *list);
~~~

# DESCRIPTION

Pass a char pointer, pointing to a null-terminated string holding the list of
cipher suites to use for the TLS 1.3 connection to a proxy. The list must be
syntactically correct, it consists of one or more cipher suite strings
separated by colons.

Find more details about cipher lists on this URL:

 https://curl.se/docs/ssl-ciphers.html

This option is currently used only when curl is built to use OpenSSL 1.1.1 or
later. If you are using a different SSL backend you can try setting TLS 1.3
cipher suites by using the CURLOPT_PROXY_SSL_CIPHER_LIST(3) option.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, use internal default

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLS13_CIPHERS,
                     "TLS_CHACHA20_POLY1305_SHA256");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.61.0.
Available when built with OpenSSL \>= 1.1.1.

# RETURN VALUE

Returns CURLE_OK if supported, CURLE_NOT_BUILT_IN otherwise.
