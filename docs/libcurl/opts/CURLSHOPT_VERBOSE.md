---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLSHOPT_VERBOSE
Section: 3
Source: libcurl
See-also:
  - CURLSHOPT_DEBUGFUNCTION (3)
  - curl_global_trace (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

CURLSHOPT_VERBOSE - verbose mode

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHOPT_VERBOSE, long onoff);
~~~

# DESCRIPTION

Set the *onoff* parameter to 1 to make the library display verbose
information about its operations on this *share handle*. Useful for
libcurl and/or protocol debugging and understanding. The verbose information
is sent to the CURLSHOPT_DEBUGFUNCTION(3).

You hardly ever want this enabled in production use, you almost always want
this used when you debug/report problems.

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLSH *share = curl_share_init();
  curl_share_setopt(share, CURLSHOPT_VERBOSE, 1L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLSHE_OK
