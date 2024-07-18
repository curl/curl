---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_init
Section: 3
Source: libcurl
See-also:
  - curl_easy_init (3)
  - curl_global_init (3)
  - curl_multi_add_handle (3)
  - curl_multi_cleanup (3)
  - curl_multi_get_handles (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

curl_multi_init - create a multi handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLM *curl_multi_init();
~~~

# DESCRIPTION

This function returns a pointer to a *CURLM* handle to be used as input to
all the other multi-functions, sometimes referred to as a multi handle in some
places in the documentation. This init call MUST have a corresponding call to
curl_multi_cleanup(3) when the operation is complete.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  CURLM *multi = curl_multi_init();
  CURL *curl = curl_easy_init();
  CURL *curl2 = curl_easy_init();

  /* add individual transfers */
  curl_multi_add_handle(multi, curl);
  curl_multi_add_handle(multi, curl2);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

If this function returns NULL, something went wrong and you cannot use the
other curl functions.
