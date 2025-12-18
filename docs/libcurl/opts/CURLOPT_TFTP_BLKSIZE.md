---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TFTP_BLKSIZE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAXFILESIZE (3)
Protocol:
  - TFTP
Added-in: 7.19.4
---

# NAME

CURLOPT_TFTP_BLKSIZE - TFTP block size

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TFTP_BLKSIZE, long blocksize);
~~~

# DESCRIPTION

Specify *blocksize* to use for TFTP data transmission. Valid range as per
RFC 2348 is 8-65464 bytes. The default of 512 bytes is used if this option is
not specified. The specified block size is only used if supported by the
remote server. If the server does not return an option acknowledgment or
returns an option acknowledgment with no block size, the default of 512 bytes
is used.

# DEFAULT

512

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "tftp://example.com/bootimage");
    /* try using larger blocks */
    curl_easy_setopt(curl, CURLOPT_TFTP_BLKSIZE, 2048L);
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
