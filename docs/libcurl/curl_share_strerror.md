---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_share_strerror
Section: 3
Source: libcurl
See-also:
  - curl_easy_strerror (3)
  - curl_multi_strerror (3)
  - curl_url_strerror (3)
  - libcurl-errors (3)
Protocol:
  - All
---

# NAME

curl_share_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <curl/curl.h>

const char *curl_share_strerror(CURLSHcode errornum);
~~~

# DESCRIPTION

The curl_share_strerror(3) function returns a string describing the
*CURLSHcode* error code passed in the argument *errornum*.

# EXAMPLE

~~~c
int main(void)
{
  CURLSHcode sh;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
  if(sh)
    printf("Error: %s\n", curl_share_strerror(sh));
}
~~~

# AVAILABILITY

This function was added in libcurl 7.12.0

# RETURN VALUE

A pointer to a null-terminated string.
