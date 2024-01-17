---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_USERAGENT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CUSTOMREQUEST (3)
  - CURLOPT_HTTPHEADER (3)
  - CURLOPT_REFERER (3)
  - CURLOPT_REQUEST_TARGET (3)
---

# NAME

CURLOPT_USERAGENT - HTTP user-agent header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_USERAGENT, char *ua);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used to set the
User-Agent: header field in the HTTP request sent to the remote server. You
can also set any custom header with CURLOPT_HTTPHEADER(3).

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, no User-Agent: header is used by default.

# PROTOCOLS

HTTP, HTTPS

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Dark Secret Ninja/1.0");

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

As long as HTTP is supported

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
