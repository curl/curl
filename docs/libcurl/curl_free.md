---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_free
Section: 3
Source: libcurl
See-also:
  - curl_easy_escape (3)
  - curl_easy_unescape (3)
Protocol:
  - All
---

# NAME

curl_free - reclaim memory that has been obtained through a libcurl call

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_free(void *ptr);
~~~

# DESCRIPTION

curl_free reclaims memory that has been obtained through a libcurl call. Use
curl_free(3) instead of free() to avoid anomalies that can result from
differences in memory management between your application and libcurl.

Passing in a NULL pointer in *ptr* makes this function return immediately
with no action.

# EXAMPLE

~~~c
int main(void)
{
  char *width = curl_getenv("COLUMNS");
  if(width) {
    /* it was set! */
    curl_free(width);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

None
