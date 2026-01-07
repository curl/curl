---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_FAILON_STATUS
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RESPONSE_CODE (3)
  - CURLOPT_FAILONERROR (3)
  - CURLOPT_KEEP_SENDING_ON_ERROR (3)
Protocol:
  - HTTP
Added-in: 8.18.0
---

# NAME

CURLOPT_FAILON_STATUS - fail on specific HTTP status codes

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_FAILON_STATUS,
                          char *codes);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string containing a comma-separated list
of HTTP status codes or ranges that should cause the request to fail. When an
HTTP response with a matching status code is received, libcurl returns
*CURLE_HTTP_RETURNED_ERROR*.

The string format supports individual codes and ranges:
- Individual codes: "404", "410"
- Ranges: "500-599" (both bounds inclusive)
- Combined: "404,410,500-599"

Ranges are inclusive on both ends. For example, "500-599" matches all codes
from 500 to 599, including both 500 and 599.

The application does not have to keep the string around after setting this
option.

When CURLOPT_FAILON_STATUS(3) is set, it takes precedence over
CURLOPT_FAILONERROR(3). If both options are set, libcurl only fails on the
exact status codes specified in CURLOPT_FAILON_STATUS(3), rather than failing
on any 400+ response.

# DEFAULT

NULL (do not fail based on status codes)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");

    /* Fail on 204 or any 5xx server error */
    curl_easy_setopt(curl, CURLOPT_FAILON_STATUS, "204,500-599");

    result = curl_easy_perform(curl);
    if(result == CURLE_HTTP_RETURNED_ERROR) {
      long response_code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
      printf("Request failed with HTTP status: %ld\n", response_code);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not,
CURLE_BAD_FUNCTION_ARGUMENT if the string format is invalid, or
CURLE_OUT_OF_MEMORY if there is insufficient memory to parse the status codes.
