---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_APPCONNECT_TIME_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_APPCONNECT_TIME (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.61.0
---

# NAME

CURLINFO_APPCONNECT_TIME_T - time until the SSL/SSH handshake completed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_APPCONNECT_TIME_T,
                           curl_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a curl_off_t to receive the time, in microseconds, it took
from the start until the SSL/SSH connect/handshake to the remote host was
completed. This time is most often close to the CURLINFO_PRETRANSFER_TIME_T(3)
time, except for cases such as HTTP multiplexing where the pretransfer time
can be delayed due to waits in line for the stream and more.

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
    curl_off_t connect;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME_T, &connect);
      if(CURLE_OK == res) {
        printf("Time: %" CURL_FORMAT_CURL_OFF_T ".%06ld", connect / 1000000,
               (long)(connect % 1000000));
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
