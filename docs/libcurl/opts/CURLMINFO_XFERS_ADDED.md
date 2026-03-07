---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMINFO_XFERS_ADDED
Section: 3
Source: libcurl
See-also:
  - CURLMINFO_XFERS_CURRENT (3)
  - CURLMINFO_XFERS_RUNNING (3)
  - CURLMINFO_XFERS_DONE (3)
Protocol:
  - All
Added-in: 8.16.0
---

# NAME

CURLMINFO_XFERS_ADDED - Cumulative number of all easy handles added

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_get_offt(CURLM *handle, CURLMINFO_XFERS_ADDED,
                              curl_off_t *pvalue);
~~~

# DESCRIPTION

The cumulative number of all easy handles added to the multi, ever. This
includes internal handles added for tasks (like resolving via DoH, for
example).

For the current number of easy handles managed by the multi, use
CURLMINFO_XFERS_CURRENT(3).

# DEFAULT

n/a

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  curl_off_t value;

  curl_multi_get_offt(m, CURLMINFO_XFERS_ADDED, &value);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_get_offt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
