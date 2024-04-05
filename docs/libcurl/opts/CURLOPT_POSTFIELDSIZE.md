---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_POSTFIELDSIZE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_POSTFIELDS (3)
  - CURLOPT_POSTFIELDSIZE_LARGE (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_POSTFIELDSIZE - size of POST data pointed to

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_POSTFIELDSIZE, long size);
~~~

# DESCRIPTION

If you want to post static data to the server without having libcurl do a
strlen() to measure the data size, this option must be used. When this option
is used you can post fully binary data, which otherwise is likely to fail. If
this size is set to -1, libcurl uses strlen() to get the size or relies on the
CURLOPT_READFUNCTION(3) (if used) to signal the end of data.

If you post more than 2GB, use CURLOPT_POSTFIELDSIZE_LARGE(3).

# DEFAULT

-1

# EXAMPLE

~~~c
#include <string.h> /* for strlen */

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    const char *data = "data to send";

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* size of the POST data */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(data));

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
