---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_add_handle
Section: 3
Source: libcurl
See-also:
  - curl_multi_cleanup (3)
  - curl_multi_get_handles (3)
  - curl_multi_init (3)
  - curl_multi_setopt (3)
  - curl_multi_socket_action (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

curl_multi_add_handle - add an easy handle to a multi session

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_add_handle(CURLM *multi_handle, CURL *easy_handle);
~~~

# DESCRIPTION

Adds the *easy handle* to the *multi_handle*.

While an easy handle is added to a multi stack, you cannot and you must not
use curl_easy_perform(3) on that handle. After having removed the easy
handle from the multi stack again, it is perfectly fine to use it with the
easy interface again.

If the easy handle is not set to use a shared (CURLOPT_SHARE(3)) cache,
it is made to use a DNS cache that is shared between all easy handles within
the multi handle when curl_multi_add_handle(3) is called.

When an easy interface is added to a multi handle, it is set to use a shared
connection cache owned by the multi handle. Removing and adding new easy
handles does not affect the pool of connections or the ability to do
connection reuse.

If you have CURLMOPT_TIMERFUNCTION(3) set in the multi handle (as you
should if you are working event-based with curl_multi_socket_action(3)
and friends), that callback is called from within this function to ask for an
updated timer so that your main event loop gets the activity on this handle to
get started.

The easy handle remains added to the multi handle until you remove it again
with curl_multi_remove_handle(3) - even when a transfer with that
specific easy handle is completed.

You should remove the easy handle from the multi stack before you terminate
first the easy handle and then the multi handle:

1 - curl_multi_remove_handle(3)

2 - curl_easy_cleanup(3)

3 - curl_multi_cleanup(3)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  CURLM *multi = curl_multi_init();

  /* create two easy handles */
  CURL *http_handle = curl_easy_init();
  CURL *http_handle2 = curl_easy_init();

  /* add individual transfers */
  curl_multi_add_handle(multi, http_handle);
  curl_multi_add_handle(multi, http_handle2);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

CURLMcode type, general libcurl multi interface error code.
