---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_SSLKEYTYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_SSLCERT (3)
  - CURLOPT_PROXY_SSLKEY (3)
  - CURLOPT_SSLKEYTYPE (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - wolfSSL
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_SSLKEYTYPE - type of the proxy private key file

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_SSLKEYTYPE, char *type);
~~~

# DESCRIPTION

This option is for connecting to an HTTPS proxy, not an HTTPS server.

Pass a pointer to a null-terminated string as parameter. The string should be
the format of your private key. Supported formats are "PEM", "DER", "ENG" and
"PROV" (the latter added in curl 8.12.0).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_PROXY, "https://proxy");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEY, "key.pem");
    curl_easy_setopt(curl, CURLOPT_PROXY_SSLKEYTYPE, "PEM");
    curl_easy_setopt(curl, CURLOPT_PROXY_KEYPASSWD, "s3cret");
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
