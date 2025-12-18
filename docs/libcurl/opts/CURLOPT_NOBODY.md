---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NOBODY
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPGET (3)
  - CURLOPT_MIMEPOST (3)
  - CURLOPT_POSTFIELDS (3)
  - CURLOPT_REQUEST_TARGET (3)
  - CURLOPT_UPLOAD (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_NOBODY - do the download request without getting the body

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NOBODY, long opt);
~~~

# DESCRIPTION

A long parameter set to 1 tells libcurl to not include the body-part in the
output when doing what would otherwise be a download. For HTTP(S), this makes
libcurl do a HEAD request. For most other protocols it means just not asking
to transfer the body data.

For HTTP operations when CURLOPT_NOBODY(3) has been set, disabling this
option (with 0) makes it a GET again - only if the method is still set to be
HEAD. The proper way to get back to a GET request is to set
CURLOPT_HTTPGET(3) and for other methods, use the POST or UPLOAD
options.

Enabling CURLOPT_NOBODY(3) means asking for a download without a body.

If you do a transfer with HTTP that involves a method other than HEAD, you get
a body (unless the resource and server sends a zero byte body for the specific
URL you request).

# DEFAULT

0, the body is transferred

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* get us the resource without a body - use HEAD */
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

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
