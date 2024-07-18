---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RTSP_CLIENT_CSEQ
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RTSP_CLIENT_CSEQ (3)
  - CURLINFO_RTSP_SERVER_CSEQ (3)
  - CURLOPT_RTSP_REQUEST (3)
  - CURLOPT_RTSP_SERVER_CSEQ (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

CURLOPT_RTSP_CLIENT_CSEQ - RTSP client CSEQ number

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RTSP_CLIENT_CSEQ, long cseq);
~~~

# DESCRIPTION

Pass a long to set the CSEQ number to issue for the next RTSP request. Useful
if the application is resuming a previously broken connection. The CSEQ
increments from this new number henceforth.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "rtsp://example.com/");
    curl_easy_setopt(curl, CURLOPT_RTSP_CLIENT_CSEQ, 1234L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
