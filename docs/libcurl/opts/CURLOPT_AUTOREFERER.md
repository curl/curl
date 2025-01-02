---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_AUTOREFERER
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EFFECTIVE_URL (3)
  - CURLINFO_REDIRECT_URL (3)
  - CURLINFO_REFERER (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - CURLOPT_REFERER (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

CURLOPT_AUTOREFERER - automatically update the referer header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_AUTOREFERER, long autorefer);
~~~

# DESCRIPTION

Pass a long parameter set to 1 to enable this. When enabled, libcurl
automatically sets the Referer: header field in HTTP requests to the full URL
when it follows a Location: redirect to a new destination.

The automatic referer is set to the full previous URL even when redirects are
done cross-origin or following redirects to insecure protocols. This is
considered a minor privacy leak by some.

With CURLINFO_REFERER(3), applications can extract the actually used
referer header after the transfer.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* follow redirects */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    /* set Referer: automatically when following redirects */
    curl_easy_setopt(curl, CURLOPT_AUTOREFERER, 1L);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
