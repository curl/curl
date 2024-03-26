---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_TIMERDATA
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_SOCKETFUNCTION (3)
  - CURLMOPT_TIMERFUNCTION (3)
Protocol:
  - All
---

# NAME

CURLMOPT_TIMERDATA - custom pointer to pass to timer callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_TIMERDATA, void *pointer);
~~~

# DESCRIPTION

A data **pointer** to pass to the timer callback set with the
CURLMOPT_TIMERFUNCTION(3) option.

This pointer is not touched by libcurl but is only be passed in to the timer
callback's **clientp** argument.

# DEFAULT

NULL

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int timerfunc(CURLM *multi, long timeout_ms, void *clientp)
{
 struct priv *mydata = clientp;
 printf("our ptr: %p\n", mydata->custom);

 if(timeout_ms) {
   /* this is the new single timeout to wait for */
 }
 else {
   /* delete the timeout, nothing to wait for now */
 }
}

int main(void)
{
  struct priv mydata;
  CURLM *multi = curl_multi_init();
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, timerfunc);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, &mydata);
}
~~~

# AVAILABILITY

Added in 7.16.0

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
