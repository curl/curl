---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CONNECTTIMEOUT_MS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECTTIMEOUT (3)
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_TIMEOUT (3)
---

# NAME

CURLOPT_CONNECTTIMEOUT_MS - timeout for the connect phase

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CONNECTTIMEOUT_MS,
                          long timeout);
~~~

# DESCRIPTION

Pass a long. It should contain the maximum time in milliseconds that you allow
the connection phase to the server to take.

See CURLOPT_CONNECTTIMEOUT(3) for details.

# DEFAULT

300000

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* complete connection within 10000 milliseconds */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 10000L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
