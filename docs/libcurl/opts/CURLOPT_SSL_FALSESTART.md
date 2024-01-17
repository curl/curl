---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_FALSESTART
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TCP_FASTOPEN (3)
---

# NAME

CURLOPT_SSL_FALSESTART - TLS false start

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_FALSESTART, long enable);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0 to disable.

This option determines whether libcurl should use false start during the TLS
handshake. False start is a mode where a TLS client starts sending application
data before verifying the server's Finished message, thus saving a round trip
when performing a full handshake.

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_SSL_FALSESTART, 1L);
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.42.0. This option is currently only supported by the Secure
Transport (on iOS 7.0 or later, or OS X 10.9 or later) TLS backend.

# RETURN VALUE

Returns CURLE_OK if false start is supported by the SSL backend, otherwise
returns CURLE_NOT_BUILT_IN.
