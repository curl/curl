---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_QUICK_EXIT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FAILONERROR (3)
  - CURLOPT_RESOLVE (3)
---

# NAME

CURLOPT_QUICK_EXIT - allow to exit quickly

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_QUICK_EXIT,
                          long value);
~~~

# DESCRIPTION

Pass a long as a parameter, 1L meaning that when recovering from a timeout,
libcurl should skip lengthy cleanups that are intended to avoid all kinds of
leaks (threads etc.), as the caller program is about to call exit() anyway.
This allows for a swift termination after a DNS timeout for example, by
canceling and/or forgetting about a resolver thread, at the expense of a
possible (though short-lived) leak of associated resources.

# DEFAULT

0

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_QUICK_EXIT, 1L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.87.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
