---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_PAUSE_STATE
Section: 3
Source: libcurl
See-also:
  - curl_easy_getinfo (3)
  - curl_easy_pause (3)
Protocol:
  - All
Added-in: 8.21.0
---

# NAME

CURLINFO_PAUSE_STATE - get the current pause state

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_PAUSE_STATE,
                           long *bitmask);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask describing the current pause
state of the transfer. The bitmask uses the same values as curl_easy_pause(3):

CURLPAUSE_RECV

: Receiving is paused.

CURLPAUSE_SEND

: Sending is paused.

If neither direction is paused, the returned value is zero.

This includes pauses set with curl_easy_pause(3) as well as pauses requested
by read or write callbacks returning CURL_READFUNC_PAUSE or
CURL_WRITEFUNC_PAUSE.

This may be used from within a callback during an active transfer. An easy
handle must not be used from multiple threads simultaneously.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    long paused;
    CURLcode result = curl_easy_getinfo(curl, CURLINFO_PAUSE_STATE, &paused);
    if(!result) {
      if(paused & CURLPAUSE_RECV)
        printf("Receiving is paused\n");
      if(paused & CURLPAUSE_SEND)
        printf("Sending is paused\n");
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
