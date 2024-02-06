---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_OS_ERRNO
Section: 3
Source: libcurl
See-also:
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_OS_ERRNO - get errno number from last connect failure

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_OS_ERRNO, long *errnop);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the errno variable from a connect failure.
Note that the value is only set on failure, it is not reset upon a successful
operation. The number is OS and system specific.

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res != CURLE_OK) {
      long error;
      res = curl_easy_getinfo(curl, CURLINFO_OS_ERRNO, &error);
      if(res && error) {
        printf("Errno: %ld\n", error);
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.12.2

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
