---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_EFFECTIVE_URL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FOLLOWLOCATION (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.4
---

# NAME

CURLINFO_EFFECTIVE_URL - get the last used URL

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_EFFECTIVE_URL, char **urlp);
~~~

# DESCRIPTION

Pass in a pointer to a char pointer and get the last used effective URL.

In cases when you have asked libcurl to follow redirects, it may not be the same
value you set with CURLOPT_URL(3).

The **urlp** pointer is NULL or points to private memory. You MUST NOT free
- it gets freed when you call curl_easy_cleanup(3) on the corresponding curl
handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      char *url = NULL;
      curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
      if(url)
        printf("Redirect to: %s\n", url);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
