---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_MAX_CONCURRENT_STREAMS
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_MAXCONNECTS (3)
  - FETCHOPT_MAXCONNECTS (3)
Protocol:
  - HTTP
Added-in: 7.67.0
---

# NAME

FETCHMOPT_MAX_CONCURRENT_STREAMS - max concurrent streams for http2

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_MAX_CONCURRENT_STREAMS,
                            long max);
~~~

# DESCRIPTION

Pass a long indicating the **max**. The set number is used as the maximum
number of concurrent streams libfetch should support on connections done using
HTTP/2 or HTTP/3.

Valid values range from 1 to 2147483647 (2^31 - 1) and defaults to 100. The
value passed here would be honored based on other system resources properties.

# DEFAULT

100

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *m = fetch_multi_init();
  /* max concurrent streams 200 */
  fetch_multi_setopt(m, FETCHMOPT_MAX_CONCURRENT_STREAMS, 200L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
