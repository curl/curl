---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_reset
Section: 3
Source: libcurl
See-also:
  - curl_easy_cleanup (3)
  - curl_easy_duphandle (3)
  - curl_easy_init (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

curl_easy_reset - reset all options of a libcurl session handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

void curl_easy_reset(CURL *handle);
~~~

# DESCRIPTION

Re-initializes all options previously set on a specified CURL handle to the
default values. This puts back the handle to the same state as it was in when
it was just created with curl_easy_init(3).

It does not change the following information kept in the handle: live
connections, the Session ID cache, the DNS cache, the cookies, the shares or
the alt-svc cache.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {

    /* ... the handle is used and options are set ... */
    curl_easy_reset(curl);
  }
}
~~~

# AVAILABILITY

This function was added in libcurl 7.12.1

# RETURN VALUE

Nothing
