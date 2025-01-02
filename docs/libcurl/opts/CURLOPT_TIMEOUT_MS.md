---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TIMEOUT_MS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CONNECTTIMEOUT (3)
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_TCP_KEEPALIVE (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.16.2
---

# NAME

CURLOPT_TIMEOUT_MS - maximum time the transfer is allowed to complete

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TIMEOUT_MS, long timeout);
~~~

# DESCRIPTION

Pass a long as parameter containing *timeout* - the maximum time in
milliseconds that you allow the libcurl transfer operation to take.

See CURLOPT_TIMEOUT(3) for details.

# DEFAULT

0 (zero) which means it never times out during transfer.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* complete within 20000 milliseconds */
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 20000L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
