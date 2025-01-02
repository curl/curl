---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_QUICK_EXIT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FAILONERROR (3)
  - CURLOPT_RESOLVE (3)
Protocol:
  - All
Added-in: 7.87.0
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

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
