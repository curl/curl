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
Added-in: 7.10.8
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

If you want a limit above 2GB, use CURLOPT_MAXFILESIZE_LARGE(3).

If the size is known to be too big before the transfer starts, libcurl
aborts before starting the transfer. If it is instead found to be too big
while the transfer is in progress, libcurl aborts the transfer once the
received bytes exceed the limit.

Since 8.20.0, this option also aborts ongoing transfers once the
decompressed bytes exceed this threshold due to automatic decompression using
CURLOPT_ACCEPT_ENCODING(3).

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* refuse to download if larger than 1000 bytes */
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE, 1000L);
    result = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# HISTORY

Before curl 8.4.0, the limit was not applied to transfers in progress.

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
