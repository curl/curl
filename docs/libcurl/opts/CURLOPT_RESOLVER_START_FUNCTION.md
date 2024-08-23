---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RESOLVER_START_FUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PREREQFUNCTION (3)
  - CURLOPT_RESOLVER_START_DATA (3)
Protocol:
  - All
Added-in: 7.59.0
---

# NAME

CURLOPT_RESOLVER_START_FUNCTION - callback called before a new name resolve is started

# SYNOPSIS

~~~c
#include <curl/curl.h>

int resolver_start_cb(void *resolver_state, void *reserved, void *userdata);

CURLcode curl_easy_setopt(CURL *handle,
                          CURLOPT_RESOLVER_START_FUNCTION,
                          resolver_start_cb);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libcurl every time before a new resolve
request is started.

*resolver_state* points to a backend-specific resolver state. Currently only
the ares resolver backend has a resolver state. It can be used to set up any
desired option on the ares channel before it is used, for example setting up
socket callback options.

*reserved* is reserved.

*userdata* is the user pointer set with the
CURLOPT_RESOLVER_START_DATA(3) option.

The callback must return 0 on success. Returning a non-zero value causes the
resolve to fail.

# DEFAULT

NULL (No callback)

# %PROTOCOLS%

# EXAMPLE

~~~c
static int start_cb(void *resolver_state, void *reserved,
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
    curl_easy_setopt(curl, CURLOPT_RESOLVER_START_FUNCTION, start_cb);
    curl_easy_setopt(curl, CURLOPT_RESOLVER_START_DATA, curl);
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
