---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_RTSP_CLIENT_CSEQ
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RTSP_CSEQ_RECV (3)
  - CURLINFO_RTSP_SERVER_CSEQ (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_RTSP_CLIENT_CSEQ - get the next RTSP client CSeq

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_RTSP_CLIENT_CSEQ,
                           long *cseq);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the next CSeq that is expected to be used
by the application.

# PROTOCOLS

RTSP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "rtsp://rtsp.example.com");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long cseq;
      curl_easy_getinfo(curl, CURLINFO_RTSP_CLIENT_CSEQ, &cseq);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.20.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
