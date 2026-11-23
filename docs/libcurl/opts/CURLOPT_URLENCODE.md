---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_URLENCODE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CURLU (3)
  - CURLOPT_PATH_AS_IS (3)
  - CURLOPT_URL (3)
  - curl_url_set (3)
Protocol:
  - All
Added-in: 8.23.1
---

# NAME

CURLOPT_URLENCODE - URL-encode the given URL

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_URLENCODE, long encode);
~~~

# DESCRIPTION

Pass a long. Set *encode* to 1 to make libcurl URL-encode the URL set with
CURLOPT_URL(3) before it is parsed. Spaces in the path and fragment are encoded
as `%20`, spaces in the query are encoded as `+`, and bytes that cannot appear
literally in a URL are encoded as `%XX`. Bytes that are already percent-encoded
are left as-is.

This makes it possible to pass a URL containing spaces or other characters
that otherwise would be rejected as malformed.

This option has no effect when CURLOPT_CURLU(3) is used.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URLENCODE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://example.com/a b?q=hello world");
    result = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
