---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_MAX_PIPELINE_LENGTH
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_MAX_HOST_CONNECTIONS (3)
  - FETCHMOPT_PIPELINING (3)
Protocol:
  - All
Added-in: 7.30.0
---

# NAME

FETCHMOPT_MAX_PIPELINE_LENGTH - maximum number of requests in a pipeline

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_MAX_PIPELINE_LENGTH,
                            long max);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a long. The set **max** number is used as the maximum amount of
outstanding requests in an HTTP/1.1 pipeline. This option is only used for
HTTP/1.1 pipelining, not for HTTP/2 multiplexing.

When this limit is reached, libfetch creates another connection to the same
host (see FETCHMOPT_MAX_HOST_CONNECTIONS(3)), or queue the request until one
    of the pipelines to the host is ready to accept a request. Thus, the total
number of requests in-flight is FETCHMOPT_MAX_HOST_CONNECTIONS(3) *
FETCHMOPT_MAX_PIPELINE_LENGTH(3).

# DEFAULT

5

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *m = fetch_multi_init();
  /* set a more conservative pipe length */
  fetch_multi_setopt(m, FETCHMOPT_MAX_PIPELINE_LENGTH, 3L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
