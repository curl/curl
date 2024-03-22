---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TRANSFER_ENCODING
Section: 3
Source: libcurl
See-also:
  - CURLOPT_ACCEPT_ENCODING (3)
  - CURLOPT_HTTP_TRANSFER_DECODING (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_TRANSFER_ENCODING - ask for HTTP Transfer Encoding

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TRANSFER_ENCODING,
                          long enable);
~~~

# DESCRIPTION

Pass a long set to 1L to *enable* or 0 to disable.

Adds a request for compressed Transfer Encoding in the outgoing HTTP
request. If the server supports this and so desires, it can respond with the
HTTP response sent using a compressed Transfer-Encoding that is automatically
uncompressed by libcurl on reception.

Transfer-Encoding differs slightly from the Content-Encoding you ask for with
CURLOPT_ACCEPT_ENCODING(3) in that a Transfer-Encoding is strictly meant
to be for the transfer and thus MUST be decoded before the data arrives in the
client. Traditionally, Transfer-Encoding has been much less used and supported
by both HTTP clients and HTTP servers.

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_TRANSFER_ENCODING, 1L);
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.21.6

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
