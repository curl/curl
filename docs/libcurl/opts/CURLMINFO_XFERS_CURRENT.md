---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMINFO_XFERS_CURRENT
Section: 3
Source: libcurl
See-also:
  - CURLMINFO_XFERS_RUNNING (3)
  - CURLMINFO_XFERS_PENDING (3)
Protocol:
  - All
Added-in: 8.16.0
---

# NAME

CURLMINFO_XFERS_CURRENT - Number of easy handles currently added

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_get_offt(CURLM *handle, CURLMINFO_XFERS_CURRENT,
                              curl_off_t *pvalue);
~~~

# DESCRIPTION

Returns the number of easy handles currently added to the multi handle. This
does not include already removed handles. It does include internal handles
that get added for tasks (like resolving via DoH, for example).

For the total number of easy handles ever added to the multi, see
CURLMINFO_XFERS_ADDED(3).

# DEFAULT

n/a

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  curl_off_t value;

  curl_multi_get_offt(m, CURLMINFO_XFERS_CURRENT, &value);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_get_offt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
