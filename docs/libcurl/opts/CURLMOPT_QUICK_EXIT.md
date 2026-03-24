---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_QUICK_EXIT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_QUICK_EXIT (3)
Protocol:
  - All
Added-in: 8.20.0
---

# NAME

CURLOPT_QUICK_EXIT - allow libcurl to exit quickly

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_QUICK_EXIT,
                            long value);
~~~

# DESCRIPTION

Pass a long as a parameter, 1L meaning that when recovering from a timeout,
libcurl should skip lengthy cleanups that are intended to avoid all kinds of
leaks (threads etc.), as the caller program is about to call exit() anyway.
This allows for a swift termination after a DNS timeout for example, by
canceling and/or forgetting about a resolver thread, at the expense of a
possible (though short-lived) leak of associated resources.

# DEFAULT

20.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* do not join threads when cleaning up this multi handle */
  curl_multi_setopt(m, CURLOPT_QUICK_EXIT, 1L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
