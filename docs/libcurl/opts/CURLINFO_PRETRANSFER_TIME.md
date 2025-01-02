---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PRETRANSFER_TIME
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CONNECT_TIME_T (3)
  - CURLINFO_PRETRANSFER_TIME_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

CURLINFO_PRETRANSFER_TIME - get the time until the file transfer start

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PRETRANSFER_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the time, in seconds, it took from the
start until the file transfer is just about to begin.

This time-stamp includes all pre-transfer commands and negotiations that are
specific to the particular protocol(s) involved. It includes the sending of
the protocol-specific instructions that trigger a transfer.

When a redirect is followed, the time from each request is added together.

See also the TIMES overview in the curl_easy_getinfo(3) man page.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    double pretransfer;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &pretransfer);
      if(CURLE_OK == res) {
        printf("Time: %.1f", pretransfer);
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
