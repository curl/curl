---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSL_CIPHER_LIST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLVERSION (3)
  - CURLOPT_PROXY_TLS13_CIPHERS (3)
  - CURLOPT_SSLVERSION (3)
  - CURLOPT_SSL_CIPHER_LIST (3)
  - CURLOPT_TLS13_CIPHERS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - BearSSL
  - Schannel
  - Secure Transport
  - wolfSSL
  - mbedTLS
  - rustls
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_SSL_CIPHER_LIST - ciphers to use for HTTPS proxy

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSL_CIPHER_LIST,
                          char *list);
~~~

# DESCRIPTION

Pass a char pointer, pointing to a null-terminated string holding the list of
cipher suites to use for the TLS 1.2 (1.1, 1.0) connection to the HTTPS proxy.
The list must be syntactically correct, it consists of one or more cipher suite
strings separated by colons.

For setting TLS 1.3 ciphers see CURLOPT_PROXY_TLS13_CIPHERS(3).

A valid example of a cipher list is:
~~~
"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
~~~

For Schannel, you can use this option to set algorithms but not specific
cipher suites. Refer to the ciphers lists document for algorithms.

Find more details about cipher lists on this URL:

 https://curl.se/docs/ssl-ciphers.html

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL, use internal built-in list.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://localhost");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSL_CIPHER_LIST,
                     "ECDHE-ECDSA-CHACHA20-POLY1305:"
                     "ECDHE-RSA-CHACHA20-POLY1305");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

OpenSSL support added in 7.52.0.
wolfSSL, Schannel, Secure Transport, and BearSSL support added in 7.87.0
mbedTLS support added in 8.8.0.
Rustls support added in 8.10.0.

Since curl 8.10.0 returns CURLE_NOT_BUILT_IN when not supported.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if supported, CURLE_NOT_BUILT_IN otherwise.
