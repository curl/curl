---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DOH_SSL_VERIFYPEER
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_CAPATH (3)
  - CURLOPT_DOH_SSL_VERIFYHOST (3)
  - CURLOPT_PROXY_SSL_VERIFYHOST (3)
  - CURLOPT_PROXY_SSL_VERIFYPEER (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
---

# NAME

CURLOPT_DOH_SSL_VERIFYPEER - verify the DoH SSL certificate

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DOH_SSL_VERIFYPEER,
                          long verify);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0L to disable.

This option tells curl to verify the authenticity of the DoH (DNS-over-HTTPS)
server's certificate. A value of 1 means curl verifies; 0 (zero) means it
does not.

This option is the DoH equivalent of CURLOPT_SSL_VERIFYPEER(3) and
only affects requests to the DoH server.

When negotiating a TLS or SSL connection, the server sends a certificate
indicating its identity. Curl verifies whether the certificate is authentic,
i.e. that you can trust that the server is who the certificate says it is.
This trust is based on a chain of digital signatures, rooted in certification
authority (CA) certificates you supply. curl uses a default bundle of CA
certificates (the path for that is determined at build time) and you can
specify alternate certificates with the CURLOPT_CAINFO(3) option or the
CURLOPT_CAPATH(3) option.

When CURLOPT_DOH_SSL_VERIFYPEER(3) is enabled, and the verification fails to
prove that the certificate is authentic, the connection fails. When the option
is zero, the peer certificate verification succeeds regardless.

Authenticating the certificate is not enough to be sure about the server. You
typically also want to ensure that the server is the server you mean to be
talking to. Use CURLOPT_DOH_SSL_VERIFYHOST(3) for that. The check that the
hostname in the certificate is valid for the hostname you are connecting to
is done independently of the CURLOPT_DOH_SSL_VERIFYPEER(3) option.

WARNING: disabling verification of the certificate allows bad guys to
man-in-the-middle the communication without you knowing it. Disabling
verification makes the communication insecure. Just having encryption on a
transfer is not enough as you cannot be sure that you are communicating with
the correct end-point.

# DEFAULT

1

# PROTOCOLS

DoH

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_DOH_URL,
                     "https://cloudflare-dns.com/dns-query");

    /* Disable certificate verification of the DoH server */
    curl_easy_setopt(curl, CURLOPT_DOH_SSL_VERIFYPEER, 0L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.76.0

If built TLS enabled.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
