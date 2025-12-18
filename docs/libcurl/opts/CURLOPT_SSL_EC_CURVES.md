---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_EC_CURVES
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_CIPHER_LIST (3)
  - CURLOPT_SSL_OPTIONS (3)
  - CURLOPT_TLS13_CIPHERS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
Added-in: 7.73.0
---

# NAME

CURLOPT_SSL_EC_CURVES - key exchange curves

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_EC_CURVES, char *list);
~~~

# DESCRIPTION

Pass a string as parameter with a colon delimited list of Elliptic curve (EC)
algorithms. This option defines the client's key exchange algorithms in the
SSL handshake (if the SSL backend libcurl is built to use supports it).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore back to internal default.

# DEFAULT

"", embedded in SSL backend

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
