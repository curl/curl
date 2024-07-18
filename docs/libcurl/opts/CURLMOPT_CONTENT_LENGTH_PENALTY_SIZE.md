---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE (3)
  - CURLMOPT_PIPELINING (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE - size threshold for pipelining penalty

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE,
                            long size);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a long with a **size** in bytes. If a transfer in a pipeline is
currently processing a request with a Content-Length larger than this
CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE(3), that pipeline is not considered
for additional requests, even if it is shorter than
CURLMOPT_MAX_PIPELINE_LENGTH(3).

# DEFAULT

0, which means that the size penalization is inactive.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  long maxlength = 10000;
  curl_multi_setopt(m, CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE, maxlength);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
