---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HSTSREADDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HSTS (3)
  - CURLOPT_HSTSREADFUNCTION (3)
  - CURLOPT_HSTSWRITEDATA (3)
  - CURLOPT_HSTSWRITEFUNCTION (3)
---

# NAME

CURLOPT_HSTSREADDATA - pointer passed to the HSTS read callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HSTSREADDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the HSTS read function. If you use the
CURLOPT_HSTSREADFUNCTION(3) option, this is the pointer you get as input
in the 3rd argument to the callback.

This option does not enable HSTS, you need to use CURLOPT_HSTS_CTRL(3) to
do that.

# DEFAULT

NULL

# PROTOCOLS

This feature is only used for HTTP(S) transfer.

# EXAMPLE

~~~c
struct MyData {
  void *custom;
};

int main(void)
{
  CURL *curl = curl_easy_init();
  struct MyData this;
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://example.com");

    /* pass pointer that gets passed in to the
       CURLOPT_HSTSREADFUNCTION callback */
    curl_easy_setopt(curl, CURLOPT_HSTSREADDATA, &this);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.74.0

# RETURN VALUE

This returns CURLE_OK.
