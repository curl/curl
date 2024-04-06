---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_RTSP_CSEQ_RECV
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RTSP_SERVER_CSEQ (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - RTSP
---

# NAME

CURLINFO_RTSP_CSEQ_RECV - get the recently received CSeq

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_RTSP_CSEQ_RECV, long *cseq);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the most recently received CSeq from the
server. If your application encounters a *CURLE_RTSP_CSEQ_ERROR* then you
may wish to troubleshoot and/or fix the CSeq mismatch by peeking at this
value.

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
      curl_easy_getinfo(curl, CURLINFO_RTSP_CSEQ_RECV, &cseq);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.20.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
