---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DOH_SSL_VERIFYHOST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DOH_SSL_VERIFYPEER (3)
  - CURLOPT_PROXY_SSL_VERIFYHOST (3)
  - CURLOPT_PROXY_SSL_VERIFYPEER (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
---

# NAME

CURLOPT_DOH_SSL_VERIFYHOST - verify the hostname in the DoH SSL certificate

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DOH_SSL_VERIFYHOST,
                          long verify);
~~~

# DESCRIPTION

Pass a long set to 2L as asking curl to *verify* the DoH (DNS-over-HTTPS)
server's certificate name fields against the hostname.

This option is the DoH equivalent of CURLOPT_SSL_VERIFYHOST(3) and
only affects requests to the DoH server.

When CURLOPT_DOH_SSL_VERIFYHOST(3) is 2, the SSL certificate provided by
the DoH server must indicate that the server name is the same as the server
name to which you meant to connect to, or the connection fails.

Curl considers the DoH server the intended one when the Common Name field or a
Subject Alternate Name field in the certificate matches the hostname in the
DoH URL to which you told Curl to connect.

When the *verify* value is set to 1L it is treated the same as 2L. However
for consistency with the other *VERIFYHOST* options we suggest use 2 and
not 1.

When the *verify* value is set to 0L, the connection succeeds regardless of
the names used in the certificate. Use that ability with caution!

See also CURLOPT_DOH_SSL_VERIFYPEER(3) to verify the digital signature
of the DoH server certificate.

# DEFAULT

2

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");

    /* Disable host name verification of the DoH server */
    curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYHOST, 0L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.76.0

If built TLS enabled.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
