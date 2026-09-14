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
Added-in: 7.16.2
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

An application that switches off transfer decoding, which is mandatory to
handle in HTTP/1.1, shoulders the responsibility of handling the response
stream and dealing with the data in a protocol compliant fashion. Disabling
decoding also disables libcurl's checks of all the transfer decoding related
headers and framing.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
    result = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
