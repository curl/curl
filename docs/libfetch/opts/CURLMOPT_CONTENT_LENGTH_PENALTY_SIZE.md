---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_CHUNK_LENGTH_PENALTY_SIZE (3)
  - FETCHMOPT_PIPELINING (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE - size threshold for pipelining penalty

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE,
                            long size);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a long with a **size** in bytes. If a transfer in a pipeline is
currently processing a request with a Content-Length larger than this
FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE(3), that pipeline is not considered
for additional requests, even if it is shorter than
FETCHMOPT_MAX_PIPELINE_LENGTH(3).

# DEFAULT

0, which means that the size penalization is inactive.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *m = fetch_multi_init();
  long maxlength = 10000;
  fetch_multi_setopt(m, FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE, maxlength);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
