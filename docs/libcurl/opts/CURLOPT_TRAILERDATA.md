---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TRAILERDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TRAILERFUNCTION (3)
  - CURLOPT_WRITEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 7.64.0
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

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
