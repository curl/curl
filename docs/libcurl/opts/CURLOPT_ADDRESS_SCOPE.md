---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_ADDRESS_SCOPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_STDERR (3)
Protocol:
  - All
Added-in: 7.19.0
---

# NAME

CURLOPT_ADDRESS_SCOPE - scope id for IPv6 addresses

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_ADDRESS_SCOPE, long scope);
~~~

# DESCRIPTION

Pass a long specifying the scope id value to use when connecting to IPv6 addresses.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <net/if.h> /* for if_nametoindex() */

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    long my_scope_id;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    my_scope_id = if_nametoindex("eth0");
    curl_easy_setopt(curl, CURLOPT_ADDRESS_SCOPE, my_scope_id);
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
Returns CURLE_BAD_FUNCTION_ARGUMENT if set to a negative value.
