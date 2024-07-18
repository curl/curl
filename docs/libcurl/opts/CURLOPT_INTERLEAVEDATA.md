---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_INTERLEAVEDATA
Section: 3
Source: libcurl
Protocol:
  - RTSP
See-also:
  - CURLOPT_INTERLEAVEFUNCTION (3)
  - CURLOPT_RTSP_REQUEST (3)
Added-in: 7.20.0
---

# NAME

CURLOPT_INTERLEAVEDATA - pointer passed to RTSP interleave callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_INTERLEAVEDATA, void *pointer);
~~~

# DESCRIPTION

This is the userdata *pointer* that is passed to
CURLOPT_INTERLEAVEFUNCTION(3) when interleaved RTP data is received. If
the interleave function callback is not set, this pointer is not used
anywhere.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct local {
  void *custom;
};
static size_t rtp_write(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct local *l = userp;
  printf("my pointer: %p\n", l->custom);
  /* take care of the packet in 'ptr', then return... */
  return size * nmemb;
}

int main(void)
{
  struct local rtp_data;
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_INTERLEAVEFUNCTION, rtp_write);
    curl_easy_setopt(curl, CURLOPT_INTERLEAVEDATA, &rtp_data);

    curl_easy_perform(curl);
 }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
