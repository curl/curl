---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_VERBOSE
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_DEBUGFUNCTION (3)
  - curl_global_trace (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLMOPT_VERBOSE - verbose mode

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_VERBOSE, long onoff);
~~~

# DESCRIPTION

Set the *onoff* parameter to 1 to make the library display verbose
information about its operations on this *multi handle*. Useful for
libcurl and/or protocol debugging and understanding. The verbose information
is sent to the CURLMOPT_DEBUGFUNCTION(3).

You hardly ever want this enabled in production use, you almost always want
this used when you debug/report problems.

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *multi = curl_multi_init();
  curl_multi_setopt(multi, CURLMOPT_VERBOSE, 1L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK
