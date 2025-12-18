---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_share_cleanup
Section: 3
Source: libcurl
See-also:
  - curl_share_init (3)
  - curl_share_setopt (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

curl_share_cleanup - close a shared object

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLSHcode curl_share_cleanup(CURLSH *share_handle);
~~~

# DESCRIPTION

This function deletes a shared object. The share handle cannot be used anymore
when this function has been called.

Passing in a NULL pointer in *share_handle* makes this function return
immediately with no action.

Any use of the **share_handle** after this function has been called and have
returned, is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLSHcode sh;
  CURLSH *share = curl_share_init();
  sh = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
  /* use the share, then ... */
  curl_share_cleanup(share);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred as *\<curl/curl.h\>* defines. See the libcurl-errors(3) man
page for the full list with descriptions. If an error occurs, then the share
object is not deleted.
