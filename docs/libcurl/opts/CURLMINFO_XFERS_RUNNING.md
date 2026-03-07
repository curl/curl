---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMINFO_XFERS_RUNNING
Section: 3
Source: libcurl
See-also:
  - CURLMINFO_XFERS_CURRENT (3)
  - CURLMINFO_XFERS_PENDING (3)
Protocol:
  - All
Added-in: 8.16.0
---

# NAME

CURLMINFO_XFERS_RUNNING - Number of easy handles currently running

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_get_offt(CURLM *handle, CURLMINFO_XFERS_RUNNING,
                              curl_off_t *pvalue);
~~~

# DESCRIPTION

The number of easy handles currently running, e.g. where the transfer has
started but not finished yet.

# DEFAULT

n/a

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  curl_off_t value;

  curl_multi_get_offt(m, CURLMINFO_XFERS_RUNNING, &value);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_get_offt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
