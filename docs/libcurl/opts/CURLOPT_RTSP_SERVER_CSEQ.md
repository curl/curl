---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RTSP_SERVER_CSEQ
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RTSP_SERVER_CSEQ (3)
  - CURLOPT_RTSP_CLIENT_CSEQ (3)
  - CURLOPT_RTSP_STREAM_URI (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

CURLOPT_RTSP_SERVER_CSEQ - RTSP server CSEQ number

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RTSP_SERVER_CSEQ, long cseq);
~~~

# DESCRIPTION

Pass a long to set the CSEQ number to expect for the next RTSP Server to
Client request. **NOTE**: this feature (listening for Server requests) is
unimplemented.

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
    curl_easy_setopt(curl, CURLOPT_RTSP_SERVER_CSEQ, 1234L);
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
