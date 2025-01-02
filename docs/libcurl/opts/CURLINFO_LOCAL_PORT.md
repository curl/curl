---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_LOCAL_PORT
Section: 3
Source: libcurl
Protocol:
  - TCP
  - QUIC
See-also:
  - CURLINFO_LOCAL_IP (3)
  - CURLINFO_PRIMARY_PORT (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Added-in: 7.21.0
---

# NAME

CURLINFO_LOCAL_PORT - get the latest local port number

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_LOCAL_PORT, long *portp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the local port number of the most recent
connection done with this **curl** handle.

If the connection was done using QUIC, the port number is a UDP port number,
otherwise it is a TCP port number.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    res = curl_easy_perform(curl);

    if(CURLE_OK == res) {
      long port;
      res = curl_easy_getinfo(curl, CURLINFO_LOCAL_PORT, &port);

      if(CURLE_OK == res) {
        printf("We used local port: %ld\n", port);
      }
    }
    curl_easy_cleanup(curl);
  }
  return 0;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
