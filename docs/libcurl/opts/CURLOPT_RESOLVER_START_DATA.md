---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RESOLVER_START_DATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PREREQFUNCTION (3)
  - CURLOPT_RESOLVER_START_FUNCTION (3)
Protocol:
  - All
Added-in: 7.59.0
---

# NAME

CURLOPT_RESOLVER_START_DATA - pointer passed to the resolver start callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RESOLVER_START_DATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* is be untouched by libcurl and passed as the third
argument in the resolver start callback set with
CURLOPT_RESOLVER_START_FUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static int resolver_start_cb(void *resolver_state, void *reserved,
                             void *userdata)
{
  (void)reserved;
  printf("Received resolver_state=%p userdata=%p\n",
         resolver_state, userdata);
  return 0;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_RESOLVER_START_FUNCTION, resolver_start_cb);
    curl_easy_setopt(curl, CURLOPT_RESOLVER_START_DATA, curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
