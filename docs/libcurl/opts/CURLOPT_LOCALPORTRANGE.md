---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_LOCALPORTRANGE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_INTERFACE (3)
  - CURLOPT_LOCALPORT (3)
---

# NAME

CURLOPT_LOCALPORTRANGE - number of additional local ports to try

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_LOCALPORTRANGE,
                          long range);
~~~

# DESCRIPTION

Pass a long. The *range* argument is the number of attempts libcurl makes
to find a working local port number. It starts with the given
CURLOPT_LOCALPORT(3) and adds one to the number for each retry. Setting
this option to 1 or below makes libcurl only do one try for the exact port
number. Port numbers by nature are scarce resources that are busy at times so
setting this value to something too low might cause unnecessary connection
setup failures.

# DEFAULT

1

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_LOCALPORT, 49152L);
    /* and try 20 more ports following that */
    curl_easy_setopt(curl, CURLOPT_LOCALPORTRANGE, 20L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.15.2

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
