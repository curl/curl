---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RTSP_STREAM_URI
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RTSP_REQUEST (3)
  - CURLOPT_RTSP_TRANSPORT (3)
---

# NAME

CURLOPT_RTSP_STREAM_URI - RTSP stream URI

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RTSP_STREAM_URI, char *URI);
~~~

# DESCRIPTION

Set the stream *URI* to operate on by passing a char * . For example, a single
session may be controlling *rtsp://foo/twister/audio* and
*rtsp://foo/twister/video* and the application can switch to the appropriate
stream using this option. If unset, libcurl defaults to operating on generic
server options by passing '*' in the place of the RTSP Stream URI. This option
is distinct from CURLOPT_URL(3). When working with RTSP, the
CURLOPT_RTSP_STREAM_URI(3) indicates what URL to send to the server in the
request header while the CURLOPT_URL(3) indicates where to make the connection
to. (e.g. the CURLOPT_URL(3) for the above examples might be set to
*rtsp://foo/twister*

The application does not have to keep the string around after setting this
option.

# DEFAULT

"*"

# PROTOCOLS

RTSP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "rtsp://example.com/");
    curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI,
                     "rtsp://foo.example.com/twister/video");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.20.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
