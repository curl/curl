---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TLSAUTH_TYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TLSAUTH_PASSWORD (3)
  - CURLOPT_TLSAUTH_USERNAME (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
---

# NAME

CURLOPT_TLSAUTH_TYPE - TLS authentication methods

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TLSAUTH_TYPE, char *type);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. The string should be
the method of the TLS authentication. Supported method is "SRP".

## SRP

TLS-SRP authentication. Secure Remote Password authentication for TLS is
defined in RFC 5054 and provides mutual authentication if both sides have a
shared secret. To use TLS-SRP, you must also set the
CURLOPT_TLSAUTH_USERNAME(3) and CURLOPT_TLSAUTH_PASSWORD(3)
options.

The application does not have to keep the string around after setting this
option.

TLS SRP does not work with TLS 1.3.

# DEFAULT

blank

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

# AVAILABILITY

You need to build libcurl with GnuTLS or OpenSSL with TLS-SRP support for this
to work. Added in 7.21.4

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
