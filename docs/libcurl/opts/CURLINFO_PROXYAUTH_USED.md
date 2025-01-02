---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PROXYAUTH_USED
Section: 3
Source: libcurl
See-also:
  - CURLINFO_HTTPAUTH_USED (3)
  - CURLINFO_PROXYAUTH_AVAIL (3)
  - CURLOPT_HTTPAUTH (3)
Protocol:
  - HTTP
Added-in: 8.12.0
---

# NAME

CURLINFO_PROXYAUTH_USED - get used HTTP proxy authentication method

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PROXYAUTH_USED, long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method that was used in the previous request done over an HTTP proxy. The
meaning of the possible bits is explained in the CURLOPT_HTTPAUTH(3) option
for curl_easy_setopt(3).

The returned value has zero or one bit set.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://proxy.example.com");
    curl_easy_setopt(curl, CURLOPT_PROXYAUTH,
                     CURLAUTH_BASIC | CURLAUTH_DIGEST);
    curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, "shrek");
    curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, "swamp");

    res = curl_easy_perform(curl);

    if(!res) {
      long auth;
      res = curl_easy_getinfo(curl, CURLINFO_PROXYAUTH_USED, &auth);
      if(!res) {
        if(!auth)
          printf("No auth used\n");
        else {
          if(auth == CURLAUTH_DIGEST)
            printf("Used Digest proxy authentication\n");
          else
            printf("Used Basic proxy authentication\n");
        }
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
