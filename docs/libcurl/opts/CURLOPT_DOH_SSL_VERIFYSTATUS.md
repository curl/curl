---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DOH_SSL_VERIFYSTATUS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DOH_SSL_VERIFYHOST (3)
  - CURLOPT_DOH_SSL_VERIFYPEER (3)
  - CURLOPT_SSL_VERIFYSTATUS (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
  - GnuTLS
Added-in: 7.76.0
---

# NAME

CURLOPT_DOH_SSL_VERIFYSTATUS - verify the DoH SSL certificate's status

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DOH_SSL_VERIFYSTATUS,
                          long verify);
~~~

# DESCRIPTION

Pass a long as parameter set to 1 to enable or 0 to disable.

This option determines whether libcurl verifies the status of the DoH
(DNS-over-HTTPS) server cert using the "Certificate Status Request" TLS
extension (aka. OCSP stapling).

This option is the DoH equivalent of CURLOPT_SSL_VERIFYSTATUS(3) and
only affects requests to the DoH server.

If this option is enabled and the server does not support the TLS extension,
the verification fails.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");

    /* Ask for OCSP stapling when verifying the DoH server */
    curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYSTATUS, 1L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if OCSP stapling is supported by the SSL backend, otherwise
returns CURLE_NOT_BUILT_IN.
