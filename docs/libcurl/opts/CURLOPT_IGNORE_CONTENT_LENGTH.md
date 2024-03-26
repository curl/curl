---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_IGNORE_CONTENT_LENGTH
Section: 3
Source: libcurl
Protocol:
  - HTTP
  - FTP
See-also:
  - CURLOPT_HTTP_VERSION (3)
  - CURLOPT_MAXFILESIZE_LARGE (3)
---

# NAME

CURLOPT_IGNORE_CONTENT_LENGTH - ignore content length

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_IGNORE_CONTENT_LENGTH,
                          long ignore);
~~~

# DESCRIPTION

If *ignore* is set to 1L, ignore the Content-Length header in the HTTP
response and ignore asking for or relying on it for FTP transfers.

This is useful for doing HTTP transfers with ancient web servers which report
incorrect content length for files over 2 gigabytes. If this option is used,
curl cannot accurately report progress, and it instead stops the download when
the server ends the connection.

It is also useful with FTP when for example the file is growing while the
transfer is in progress which otherwise unconditionally causes libcurl to
report error.

Only use this option if strictly necessary.

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* we know the server is silly, ignore content-length */
    curl_easy_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, 1L);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.14.1. Support for FTP added in 7.46.0. This option is not working
for HTTP when libcurl is built to use the hyper backend.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
