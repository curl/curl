---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_USED_PROXY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NOPROXY (3)
  - CURLOPT_PROXY (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 8.7.0
---

# NAME

CURLINFO_USED_PROXY - whether the transfer used a proxy

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_USED_PROXY,
                           long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long. It gets set to zero set if no proxy was used in the
previous transfer or a non-zero value if a proxy was used.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char *argv[])
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:80");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, "example.com");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract the available proxy authentication types */
      long used;
      res = curl_easy_getinfo(curl, CURLINFO_USED_PROXY, &used);
      if(!res) {
        printf("The proxy was %sused\n", used ? "": "NOT ");
      }
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
