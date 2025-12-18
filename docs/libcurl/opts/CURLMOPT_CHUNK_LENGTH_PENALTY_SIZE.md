---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_CONTENT_LENGTH_PENALTY_SIZE (3)
  - CURLMOPT_MAX_PIPELINE_LENGTH (3)
  - CURLMOPT_PIPELINING (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE - chunk length threshold for pipelining

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE,
                            long size);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a long with a **size** in bytes. If a transfer in a pipeline is
currently processing a chunked (Transfer-encoding: chunked) request with a
current chunk length larger than CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE(3),
that pipeline is not considered for additional requests, even if it is shorter
than CURLMOPT_MAX_PIPELINE_LENGTH(3).

# DEFAULT

0, which means that penalization is inactive.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  long maxchunk = 10000;
  curl_multi_setopt(m, CURLMOPT_CHUNK_LENGTH_PENALTY_SIZE, maxchunk);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_multi_setopt(3) returns a CURLMcode indicating success or error.

CURLM_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
