---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_url_strerror
Section: 3
Source: libcurl
See-also:
  - curl_easy_strerror (3)
  - curl_multi_strerror (3)
  - curl_share_strerror (3)
  - curl_url_get (3)
  - curl_url_set (3)
  - libcurl-errors (3)
Protocol:
  - All
---

# NAME

curl_url_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <curl/curl.h>

const char *curl_url_strerror(CURLUcode errornum);
~~~

# DESCRIPTION

This function returns a string describing the CURLUcode error code passed in
the argument *errornum*.

# EXAMPLE

~~~c
int main(void)
{
  CURLUcode rc;
  CURLU *url = curl_url();
  rc = curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
  if(rc)
    printf("URL error: %s\n", curl_url_strerror(rc));
  curl_url_cleanup(url);
}
~~~

# AVAILABILITY

Added in 7.80.0

# RETURN VALUE

A pointer to a null-terminated string.
