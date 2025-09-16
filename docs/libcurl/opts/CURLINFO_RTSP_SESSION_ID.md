---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_RTSP_SESSION_ID
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RTSP_CSEQ_RECV (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - RTSP
Added-in: 7.20.0
---

# NAME

CURLINFO_RTSP_SESSION_ID - get RTSP session ID

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_RTSP_SESSION_ID, char **id);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive a pointer to a string holding the
most recent RTSP Session ID.

Applications wishing to resume an RTSP session on another connection should
retrieve this info before closing the active connection.

The **id** pointer is NULL or points to private memory. You **must not** free
it. The memory gets freed automatically when you call curl_easy_cleanup(3) on
the corresponding curl handle.

# %PROTOCOLS%

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
      char *id;
      curl_easy_getinfo(curl, CURLINFO_RTSP_SESSION_ID, &id);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
