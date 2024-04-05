---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP_TRANSFER_DECODING
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_ACCEPT_ENCODING (3)
  - CURLOPT_HTTP_CONTENT_DECODING (3)
---

# NAME

CURLOPT_HTTP_TRANSFER_DECODING - HTTP transfer decoding control

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP_TRANSFER_DECODING,
                         long enabled);
~~~

# DESCRIPTION

Pass a long to tell libcurl how to act on transfer decoding. If set to zero,
transfer decoding is disabled, if set to 1 it is enabled (default). libcurl
does chunked transfer decoding by default unless this option is set to zero.

# DEFAULT

1

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.16.2 Does not work with the hyper backend (it always has transfer
decoding enabled).

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
