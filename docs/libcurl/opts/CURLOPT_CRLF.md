---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CRLF
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONV_FROM_NETWORK_FUNCTION (3)
  - CURLOPT_CONV_TO_NETWORK_FUNCTION (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_CRLF - CRLF conversion

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CRLF, long conv);
~~~

# DESCRIPTION

Pass a long. If the value is set to 1 (one), libcurl converts Unix newlines to
CRLF newlines on transfers. Disable this option again by setting the value to
0 (zero).

This is a legacy option of questionable use.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/");
    curl_easy_setopt(curl, CURLOPT_CRLF, 1L);
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
