---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_RTSP_SESSION_ID
Section: 3
Source: libcurl
See-also:
  - CURLOPT_RTSP_REQUEST (3)
  - CURLOPT_RTSP_STREAM_URI (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

CURLOPT_RTSP_SESSION_ID - RTSP session ID

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_RTSP_SESSION_ID, char *id);
~~~

# DESCRIPTION

Pass a char pointer as a parameter to set the value of the current RTSP
Session ID for the handle. Useful for resuming an in-progress session. Once
this value is set to any non-NULL value, libcurl returns
*CURLE_RTSP_SESSION_ERROR* if ID received from the server does not match. If
unset (or set to NULL), libcurl automatically sets the ID the first time the
server sets it in a response.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    char *prev_id; /* saved from before somehow */
    curl_easy_setopt(curl, CURLOPT_URL, "rtsp://example.com/");
    curl_easy_setopt(curl, CURLOPT_RTSP_SESSION_ID, prev_id);
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
