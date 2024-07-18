---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_strerror
Section: 3
Source: libcurl
See-also:
  - curl_easy_strerror (3)
  - curl_share_strerror (3)
  - curl_url_strerror (3)
  - libcurl-errors (3)
Protocol:
  - All
Added-in: 7.12.0
---

# NAME

curl_multi_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <curl/curl.h>

const char *curl_multi_strerror(CURLMcode errornum);
~~~

# DESCRIPTION

This function returns a string describing the *CURLMcode* error code
passed in the argument *errornum*.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  int still_running;
  CURLM *multi = curl_multi_init();

  CURLMcode mc = curl_multi_perform(multi, &still_running);
  if(mc)
    printf("error: %s\n", curl_multi_strerror(mc));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string.
