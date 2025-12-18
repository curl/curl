---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_strerror
Section: 3
Source: libcurl
See-also:
  - curl_multi_strerror (3)
  - curl_share_strerror (3)
  - curl_url_strerror (3)
  - libcurl-errors (3)
Protocol:
  - All
Added-in: 7.12.0
---

# NAME

curl_easy_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <curl/curl.h>

const char *curl_easy_strerror(CURLcode errornum);
~~~

# DESCRIPTION

The curl_easy_strerror(3) function returns a string describing the
CURLcode error code passed in the argument *errornum*.

Typically applications also appreciate CURLOPT_ERRORBUFFER(3) for more
specific error descriptions generated at runtime.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    /* set options */
    /* Perform the entire transfer */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string.
