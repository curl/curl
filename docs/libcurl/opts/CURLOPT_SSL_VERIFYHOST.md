---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_VERIFYHOST
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_PINNEDPUBLICKEY (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - All
---

# NAME

CURLOPT_SSL_VERIFYHOST - verify the certificate's name against host

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_VERIFYHOST, long verify);
~~~

# DESCRIPTION

Pass a long as parameter specifying what to *verify*.

This option determines whether libcurl verifies that the server cert is for
the server it is known as.

When negotiating TLS and SSL connections, the server sends a certificate
indicating its identity.

When CURLOPT_SSL_VERIFYHOST(3) is 2, that certificate must indicate that
the server is the server to which you meant to connect, or the connection
fails. Simply put, it means it has to have the same name in the certificate as
is in the URL you operate against.

Curl considers the server the intended one when the Common Name field or a
Subject Alternate Name field in the certificate matches the hostname in the
URL to which you told Curl to connect.

If *verify* value is set to 1:

In 7.28.0 and earlier: treated as a debug option of some sorts, not supported
anymore due to frequently leading to programmer mistakes.

From 7.28.1 to 7.65.3: setting it to 1 made curl_easy_setopt(3) return
an error and leaving the flag untouched.

From 7.66.0: treats 1 and 2 the same.

When the *verify* value is 0, the connection succeeds regardless of the
names in the certificate. Use that ability with caution!

The default value for this option is 2.

This option controls checking the server's certificate's claimed identity.
The server could be lying. To control lying, see CURLOPT_SSL_VERIFYPEER(3).

WARNING: disabling verification of the certificate allows bad guys to
man-in-the-middle the communication without you knowing it. Disabling
verification makes the communication insecure. Just having encryption on a
transfer is not enough as you cannot be sure that you are communicating with
the correct end-point.

When libcurl uses secure protocols it trusts responses and allows for example
HSTS and Alt-Svc information to be stored and used subsequently. Disabling
certificate verification can make libcurl trust and use such information from
malicious servers.

# LIMITATIONS

Secure Transport: If *verify* value is 0, then SNI is also disabled. SNI is
a TLS extension that sends the hostname to the server. The server may use that
information to do such things as sending back a specific certificate for the
hostname, or forwarding the request to a specific origin server. Some hostnames
may be inaccessible if SNI is not sent.

# DEFAULT

2

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Set the default value: strict name check please */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

If built TLS enabled.

# RETURN VALUE

Returns CURLE_OK if TLS is supported, and CURLE_UNKNOWN_OPTION if not.

If 1 is set as argument, *CURLE_BAD_FUNCTION_ARGUMENT* is returned.
