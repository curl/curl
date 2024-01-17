---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_MAX_PIPELINE_LENGTH
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_MAX_HOST_CONNECTIONS (3)
  - CURLMOPT_PIPELINING (3)
---

# NAME

CURLMOPT_MAX_PIPELINE_LENGTH - maximum number of requests in a pipeline

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_MAX_PIPELINE_LENGTH,
                            long max);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a long. The set **max** number is used as the maximum amount of
outstanding requests in an HTTP/1.1 pipeline. This option is only used for
HTTP/1.1 pipelining, not for HTTP/2 multiplexing.

When this limit is reached, libcurl creates another connection to the same
host (see CURLMOPT_MAX_HOST_CONNECTIONS(3)), or queue the request until one
    of the pipelines to the host is ready to accept a request. Thus, the total
number of requests in-flight is CURLMOPT_MAX_HOST_CONNECTIONS(3) *
CURLMOPT_MAX_PIPELINE_LENGTH(3).

# DEFAULT

5

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* set a more conservative pipe length */
  curl_multi_setopt(m, CURLMOPT_MAX_PIPELINE_LENGTH, 3L);
}
~~~

# AVAILABILITY

Added in 7.30.0

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
