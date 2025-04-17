---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSLCERTTYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSLCERT (3)
  - CURLOPT_SSLKEY (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
  - mbedTLS
  - Schannel
  - wolfSSL
Added-in: 7.9.3
---

# NAME

CURLOPT_SSLCERTTYPE - type of client SSL certificate

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSLCERTTYPE, char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the format of your certificate.

Supported formats are "PEM" and "DER", except with Schannel. OpenSSL and
Schannel support "P12" for PKCS#12-encoded files. GnuTLS supports P12 starting
with curl 8.11.0.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL restores back to internal default.

# DEFAULT

"PEM"

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(curl, CURLOPT_SSLKEY, "key.pem");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "s3cret");
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
