---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_UPLOAD_BUFFERSIZE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_BUFFERSIZE (3)
  - CURLOPT_READFUNCTION (3)
  - CURLOPT_TCP_NODELAY (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

CURLOPT_UPLOAD_BUFFERSIZE - upload buffer size

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_UPLOAD_BUFFERSIZE, long size);
~~~

# DESCRIPTION

Pass a long specifying your preferred *size* (in bytes) for the upload
buffer in libcurl. It makes libcurl uses a larger buffer that gets passed to
the next layer in the stack to get sent off. In some setups and for some
protocols, there is a huge performance benefit of having a larger upload
buffer.

This is just treated as a request, not an order. You cannot be guaranteed to
actually get the given size.

The upload buffer size is by default 64 kilobytes. The maximum buffer size
allowed to be set is 2 megabytes. The minimum buffer size allowed to be set is
16 kilobytes.

The upload buffer is allocated on-demand - so if the handle is not used for
upload, this buffer is not allocated at all.

DO NOT set this option on a handle that is currently used for an active
transfer as that may lead to unintended consequences.

# DEFAULT

65536 bytes

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "sftp://example.com/foo.bin");

    /* ask libcurl to allocate a larger upload buffer */
    curl_easy_setopt(curl, CURLOPT_UPLOAD_BUFFERSIZE, 120000L);

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
