---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP_CONTENT_DECODING
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_ACCEPT_ENCODING (3)
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_STDERR (3)
Added-in: 7.16.2
---

# NAME

CURLOPT_HTTP_CONTENT_DECODING - HTTP content decoding control

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP_CONTENT_DECODING,
                          long enabled);
~~~

# DESCRIPTION

Pass a long to tell libcurl how to act on content decoding. If set to zero,
content decoding is disabled. If set to 1 it is enabled. libcurl has no
default content decoding but requires you to use
CURLOPT_ACCEPT_ENCODING(3) for that.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
