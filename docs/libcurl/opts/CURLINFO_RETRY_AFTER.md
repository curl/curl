---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_RETRY_AFTER
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERFUNCTION (3)
  - CURLOPT_STDERR (3)
  - curl_easy_header (3)
---

# NAME

CURLINFO_RETRY_AFTER - returns the Retry-After retry delay

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_RETRY_AFTER,
                           curl_off_t *retry);
~~~

# DESCRIPTION

Pass a pointer to a curl_off_t variable to receive the number of seconds the
HTTP server suggests the client should wait until the next request is
issued. The information from the "Retry-After:" header.

While the HTTP header might contain a fixed date string, the
CURLINFO_RETRY_AFTER(3) always returns the number of seconds to wait -
or zero if there was no header or the header could not be parsed.

# DEFAULT

Returns zero delay if there was no header.

# PROTOCOLS

HTTP(S)

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
      curl_off_t wait = 0;
      curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &wait);
      if(wait)
        printf("Wait for %" CURL_FORMAT_CURL_OFF_T " seconds\n", wait);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.66.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
