---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_REFERER
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_URL (3)
  - CURLINFO_REFERER (3)
  - CURLOPT_HTTPHEADER (3)
  - CURLOPT_USERAGENT (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_REFERER - the HTTP referer header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_REFERER, char *where);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used to set the
Referer: header field in the HTTP request sent to the remote server. You can
set any custom header with CURLOPT_HTTPHEADER(3).

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* tell it where we found the link to this place */
    curl_easy_setopt(curl, CURLOPT_REFERER, "https://example.org/me.html");

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

If built with HTTP support

# RETURN VALUE

Returns CURLE_OK if HTTP support is enabled, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
