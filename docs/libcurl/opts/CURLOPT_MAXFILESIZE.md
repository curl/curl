---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAXFILESIZE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAXFILESIZE_LARGE (3)
  - CURLOPT_MAX_RECV_SPEED_LARGE (3)
Protocol:
  - All
---

# NAME

CURLOPT_MAXFILESIZE - maximum file size allowed to download

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAXFILESIZE, long size);
~~~

# DESCRIPTION

Pass a long as parameter. This specifies the maximum accepted *size* (in
bytes) of a file to download. If the file requested is found larger than this
value, the transfer is aborted and *CURLE_FILESIZE_EXCEEDED* is returned.
Passing a zero *size* disables this, and passing a negative *size* yields a
*CURLE_BAD_FUNCTION_ARGUMENT*.

The file size is not always known prior to the download start, and for such
transfers this option has no effect - even if the file transfer eventually
ends up being larger than this given limit.

If you want a limit above 2GB, use CURLOPT_MAXFILESIZE_LARGE(3).

Since 8.4.0, this option also stops ongoing transfers if they reach this
threshold.

# DEFAULT

0, meaning disabled.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* refuse to download if larger than 1000 bytes! */
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 1000L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK if the size passed is valid or CURLE_BAD_FUNCTION_ARGUMENT if
not.
