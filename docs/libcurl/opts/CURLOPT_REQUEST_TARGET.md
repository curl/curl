---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_REQUEST_TARGET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CUSTOMREQUEST (3)
  - CURLOPT_HTTPGET (3)
  - CURLOPT_PATH_AS_IS (3)
  - CURLOPT_URL (3)
Protocol:
  - HTTP
Added-in: 7.55.0
---

# NAME

CURLOPT_REQUEST_TARGET - alternative target for this request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_REQUEST_TARGET, string);
~~~

# DESCRIPTION

Pass a char pointer to string which libcurl uses in the upcoming request
instead of the path as extracted from the URL.

libcurl passes on the verbatim string in its request without any filter or
other safe guards. That includes white space and control characters.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/*");
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "OPTIONS");

    /* issue an OPTIONS * request (no leading slash) */
    curl_easy_setopt(curl, CURLOPT_REQUEST_TARGET, "*");

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
