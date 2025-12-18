---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PRIMARY_PORT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_LOCAL_PORT (3)
  - CURLINFO_PRIMARY_IP (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.21.0
---

# NAME

CURLINFO_PRIMARY_PORT - get the latest destination port number

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PRIMARY_PORT, long *portp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the destination port of the most recent
connection done with this **curl** handle.

This is the destination port of the actual TCP or UDP connection libcurl used.
If a proxy was used for the most recent transfer, this is the port number of
the proxy, if no proxy was used it is the port number of the most recently
accessed URL.

# %PROTOCOLS%

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
      long port;
      res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &port);
      if(!res)
        printf("Connected to remote port: %ld\n", port);
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
