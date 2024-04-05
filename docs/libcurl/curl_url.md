---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_url
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CURLU (3)
  - curl_url_cleanup (3)
  - curl_url_dup (3)
  - curl_url_get (3)
  - curl_url_set (3)
  - curl_url_strerror (3)
Protocol:
  - All
---

# NAME

curl_url - returns a new URL handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLU *curl_url();
~~~

# DESCRIPTION

This function allocates a URL object and returns a *CURLU* handle for it,
to be used as input to all other URL API functions.

This is a handle to a URL object that holds or can hold URL components for a
single URL. When the object is first created, there is of course no components
stored. They are then set in the object with the curl_url_set(3)
function.

# EXAMPLE

~~~c
int main(void)
{
  CURLUcode rc;
  CURLU *url = curl_url();
  rc = curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
  if(!rc) {
    char *scheme;
    rc = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    if(!rc) {
      printf("the scheme is %s\n", scheme);
      curl_free(scheme);
    }
    curl_url_cleanup(url);
  }
}
~~~

# AVAILABILITY

Added in 7.62.0

# RETURN VALUE

Returns a **CURLU *** if successful, or NULL if out of memory.
