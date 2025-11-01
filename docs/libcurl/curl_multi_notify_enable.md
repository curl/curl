---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_multi_notify_enable
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_NOTIFYFUNCTION (3)
  - CURLMOPT_NOTIFYDATA (3)
  - curl_multi_notify_disable (3)
Protocol:
  - All
Added-in: 8.17.0
---

# NAME

curl_multi_notify_enable - enable a notification type

# SYNOPSIS

~~~c
#include <curl/curl.h>
CURLMcode curl_multi_notify_enable(CURLM *multi_handle,
                                   unsigned int notification);
~~~

# DESCRIPTION

Enables collecting the given notification type in the multi handle. A
callback function installed via CURLMOPT_NOTIFYFUNCTION(3) is called
when this notification happens.

Only when a notification callback is installed *and* a notification
is enabled are these collected and dispatched to the callback.

Several notification types can be enabled at the same time. Enabling
an already enabled notification is not an error.

A notification can be disabled again via curl_multi_notify_disable(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  int rc;
  CURLM *multi = curl_multi_init();

  rc = curl_multi_notify_enable(multi, CURLMNOTIFY_INFO_READ);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).

The return code is for the whole multi stack. Problems still might have
occurred on individual transfers even when one of these functions return OK.
