---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TLSAUTH_PASSWORD
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY_TLSAUTH_PASSWORD (3)
  - CURLOPT_TLSAUTH_TYPE (3)
  - CURLOPT_TLSAUTH_USERNAME (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.21.4
---

# NAME

CURLOPT_TLSAUTH_PASSWORD - password to use for TLS authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TLSAUTH_PASSWORD, char *pwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
password to use for the TLS authentication method specified with the
CURLOPT_TLSAUTH_TYPE(3) option. Requires that the CURLOPT_TLSAUTH_USERNAME(3)
option also be set.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

This feature relies on TLS SRP which does not work with TLS 1.3.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_TLSAUTH_TYPE, "SRP");
    curl_easy_setopt(curl, CURLOPT_TLSAUTH_USERNAME, "user");
    curl_easy_setopt(curl, CURLOPT_TLSAUTH_PASSWORD, "secret");
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
