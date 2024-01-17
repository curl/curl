---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TRAILERDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TRAILERFUNCTION (3)
  - CURLOPT_WRITEFUNCTION (3)
---

# NAME

CURLOPT_TRAILERDATA - pointer passed to trailing headers callback

# SYNOPSIS

~~~c
#include <curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TRAILERDATA, void *userdata);
~~~

# DESCRIPTION

Data pointer to be passed to the HTTP trailer callback function.

# DEFAULT

NULL

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
struct MyData {
  void *custom;
};

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    struct MyData data;
    curl_easy_setopt(curl, CURLOPT_TRAILERDATA, &data);
  }
}
~~~

# AVAILABILITY

This option was added in curl 7.64.0 and is present if HTTP support is enabled

# RETURN VALUE

Returns CURLE_OK.
