---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_VERIFYSTATUS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_SSL_VERIFYSTATUS - verify the certificate's status

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_VERIFYSTATUS, long verify);
~~~

# DESCRIPTION

Pass a long as parameter set to 1 to enable or 0 to disable.

This option determines whether libcurl verifies the status of the server cert
using the "Certificate Status Request" TLS extension (aka. OCSP stapling).

Note that if this option is enabled but the server does not support the TLS
extension, the verification fails.

# DEFAULT

0

# PROTOCOLS

All TLS based protocols: HTTPS, FTPS, IMAPS, POP3S, SMTPS etc.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* ask for OCSP stapling! */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.41.0. This option is currently only supported by the OpenSSL and
GnuTLS TLS backends.

# RETURN VALUE

Returns CURLE_OK if OCSP stapling is supported by the SSL backend, otherwise
returns CURLE_NOT_BUILT_IN.
