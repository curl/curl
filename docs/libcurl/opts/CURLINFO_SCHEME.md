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
---

# NAME

CURLINFO_SCHEME - get the URL scheme (sometimes called protocol) used in the connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SCHEME, char **scheme);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the URL scheme used for the most recent connection done with
this CURL **handle**.

The **scheme** pointer is NULL or points to private memory. You MUST NOT
free - it gets freed when you call curl_easy_cleanup(3) on the corresponding
CURL handle.

The returned scheme might be upper or lowercase. Do comparisons case
insensitively.

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
      char *scheme = NULL;
      curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
      if(scheme)
        printf("scheme: %s\n", scheme); /* scheme: HTTP */
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.52.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
