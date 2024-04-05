---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_get_handles
Section: 3
Source: libcurl
See-also:
  - curl_multi_add_handle (3)
  - curl_multi_cleanup (3)
  - curl_multi_init (3)
  - curl_multi_remove_handle (3)
Protocol:
  - All
---

# NAME

curl_multi_get_handles - returns all added easy handles

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURL **curl_multi_get_handles(CURLM *multi_handle);
~~~

# DESCRIPTION

Returns an array with pointers to all added easy handles. The end of the list
is marked with a NULL pointer.

Even if there is not a single easy handle added, this still returns an array
but with only a single NULL pointer entry.

The returned array contains all the handles that are present at the time of
the call. As soon as a handle has been removed from or a handle has been added
to the multi handle after the handle array was returned, the two data points
are out of sync.

The order of the easy handles within the array is not guaranteed.

The returned array must be freed with a call to curl_free(3) after use.

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  CURLM *multi = curl_multi_init();
  CURL *curl = curl_easy_init();

  if(curl) {
    /* add the transfer */
    curl_multi_add_handle(multi, curl);

    /* extract all added handles */
    CURL **list = curl_multi_get_handles(multi);

    if(list) {
      int i;
      /* remove all added handles */
      for(i = 0; list[i]; i++) {
        curl_multi_remove_handle(multi, list[i]);
      }
      curl_free(list);
    }
  }
}
~~~

# AVAILABILITY

Added in 8.4.0

# RETURN VALUE

Returns NULL on failure. Otherwise it returns a pointer to an allocated array.
