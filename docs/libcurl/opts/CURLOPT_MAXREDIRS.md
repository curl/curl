---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAXREDIRS
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLINFO_REDIRECT_URL (3)
  - CURLOPT_FOLLOWLOCATION (3)
Protocol:
  - HTTP
Added-in: 7.5
---

# NAME

CURLOPT_MAXREDIRS - maximum number of redirects allowed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAXREDIRS, long amount);
~~~

# DESCRIPTION

Pass a long. The set number is the redirection limit *amount*. If that
many redirections have been followed, the next redirect triggers the error
(*CURLE_TOO_MANY_REDIRECTS*). This option only makes sense if the
CURLOPT_FOLLOWLOCATION(3) is used at the same time.

Setting the limit to 0 makes libcurl refuse any redirect.

Set it to -1 for an infinite number of redirects. This allows your application
to get stuck in never-ending redirect loops.

# DEFAULT

30 (since 8.3.0), it was previously unlimited.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");

    /* enable redirect following */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* allow three redirects */
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
