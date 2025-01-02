---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_LOCALPORT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_LOCAL_PORT (3)
  - CURLOPT_INTERFACE (3)
  - CURLOPT_LOCALPORTRANGE (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

CURLOPT_LOCALPORT - local port number to use for socket

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_LOCALPORT, long port);
~~~

# DESCRIPTION

Pass a long. This sets the local port number of the socket used for the
connection. This can be used in combination with CURLOPT_INTERFACE(3)
and you are recommended to use CURLOPT_LOCALPORTRANGE(3) as well when
this option is set. Valid port numbers are 1 - 65535.

# DEFAULT

0, disabled - use whatever the system thinks is fine

# %PROTOCOLS%

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

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
