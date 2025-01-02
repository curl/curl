---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_HTTPAUTH_USED
Section: 3
Source: libcurl
See-also:
  - CURLINFO_PROXYAUTH_USED (3)
  - CURLINFO_HTTPAUTH_AVAIL (3)
  - CURLOPT_HTTPAUTH (3)
Protocol:
  - HTTP
Added-in: 8.12.0
---

# NAME

CURLINFO_HTTPAUTH_USED - get used HTTP authentication method

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_HTTPAUTH_USED, long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method that was used in the previous HTTP request. The meaning of the possible
bits is explained in the CURLOPT_HTTPAUTH(3) option for curl_easy_setopt(3).

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
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_DIGEST);
    curl_easy_setopt(curl, CURLOPT_USERNAME, "shrek");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "swamp");

    res = curl_easy_perform(curl);

    if(!res) {
      long auth;
      res = curl_easy_getinfo(curl, CURLINFO_HTTPAUTH_USED, &auth);
      if(!res) {
        if(!auth)
          printf("No auth used\n");
        else {
          if(auth == CURLAUTH_DIGEST)
            printf("Used Digest authentication\n");
          else
            printf("Used Basic authentication\n");
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
