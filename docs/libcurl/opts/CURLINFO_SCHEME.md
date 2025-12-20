---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SCHEME
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EFFECTIVE_URL (3)
  - CURLINFO_PROTOCOL (3)
  - CURLINFO_RESPONSE_CODE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.52.0
---

# NAME

CURLINFO_SCHEME - URL scheme used in transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SCHEME, char **scheme);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the URL scheme used for the most recent transfer done with this
CURL **handle**. The scheme might also sometimes be referred to as the
protocol.

The **scheme** pointer is NULL or points to private memory. You **must not**
free it. The memory gets freed automatically when you call
curl_easy_cleanup(3) on the corresponding curl handle.

The returned scheme might be upper or lowercase. Do comparisons case
insensitively.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    result = curl_easy_perform(curl);
    if(result == CURLE_OK) {
      char *scheme = NULL;
      curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
      if(scheme)
        printf("scheme: %s\n", scheme); /* scheme: HTTP */
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
