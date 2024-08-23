---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RTSP_TRANSPORT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RTSP_REQUEST (3)
  - CURLOPT_RTSP_SESSION_ID (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

CURLOPT_RTSP_TRANSPORT - RTSP Transport: header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RTSP_TRANSPORT,
                          char *transport);
~~~

# DESCRIPTION

Pass a char pointer to tell libcurl what to pass for the Transport: header for
this RTSP session. This is mainly a convenience method to avoid needing to set
a custom Transport: header for every SETUP request. The application must set a
Transport: header before issuing a SETUP request.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "rtsp://example.com/");
    curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
    curl_easy_setopt(curl, CURLOPT_RTSP_TRANSPORT,
                     "RTP/AVP;unicast;client_port=4588-4589");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
