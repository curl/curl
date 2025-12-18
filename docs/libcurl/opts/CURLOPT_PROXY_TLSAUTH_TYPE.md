---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_PROXY_TLSAUTH_TYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_TLSAUTH_PASSWORD (3)
  - CURLOPT_PROXY_TLSAUTH_USERNAME (3)
  - CURLOPT_TLSAUTH_PASSWORD (3)
  - CURLOPT_TLSAUTH_USERNAME (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.52.0
---

# NAME

CURLOPT_PROXY_TLSAUTH_TYPE - HTTPS proxy TLS authentication methods

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_PROXY_TLSAUTH_TYPE,
                          char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the method of the TLS authentication used for the HTTPS connection. Supported
method is "SRP".

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to restore to internal default.

The application does not have to keep the string around after setting this
option.

## SRP

TLS-SRP authentication. Secure Remote Password authentication for TLS is
defined in RFC 5054 and provides mutual authentication if both sides have a
shared secret. To use TLS-SRP, you must also set the
CURLOPT_PROXY_TLSAUTH_USERNAME(3) and CURLOPT_PROXY_TLSAUTH_PASSWORD(3)
options.

# DEFAULT

blank

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
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_TYPE, "SRP");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_PROXY_TLSAUTH_PASSWORD, "secret");
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
