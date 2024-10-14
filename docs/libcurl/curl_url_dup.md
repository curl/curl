---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_url_dup
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CURLU (3)
  - curl_url (3)
  - curl_url_cleanup (3)
  - curl_url_get (3)
  - curl_url_set (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

curl_url_dup - duplicate a URL handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLU *curl_url_dup(const CURLU *inhandle);
~~~

# DESCRIPTION

Duplicates the URL object the input *CURLU* *inhandle* identifies and
returns a pointer to the copy as a new *CURLU* handle. The new handle also
needs to be freed with curl_url_cleanup(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLUcode rc;
  CURLU *url = curl_url();
  CURLU *url2;
  rc = curl_url_set(url, CURLUPART_URL, "https://example.com", 0);
  if(!rc) {
    url2 = curl_url_dup(url); /* clone it */
    curl_url_cleanup(url2);
  }
  curl_url_cleanup(url);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a new handle or NULL if out of memory.
