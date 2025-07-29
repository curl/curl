---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_FALSESTART
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TCP_FASTOPEN (3)
Protocol:
  - TLS
TLS-backend:
  - none
Added-in: 7.42.0
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

# %PROTOCOLS%

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

# DEPRECATED

Deprecated since 8.15.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
