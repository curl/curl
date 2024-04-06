---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_REDIRECT_URL
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLINFO_REDIRECT_TIME_T (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
---

# NAME

CURLINFO_REDIRECT_URL - get the URL a redirect would go to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_REDIRECT_URL, char **urlp);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the URL a redirect *would*
take you to if you would enable CURLOPT_FOLLOWLOCATION(3). This can come
handy if you think using the built-in libcurl redirect logic is not good enough
for you but you would still prefer to avoid implementing all the magic of
figuring out the new URL.

This URL is also set if the CURLOPT_MAXREDIRS(3) limit prevented a
redirect to happen (since 7.54.1).

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      char *url = NULL;
      curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &url);
      if(url)
        printf("Redirect to: %s\n", url);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.18.2

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
