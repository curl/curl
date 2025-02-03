---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_PIPELINING
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_CHUNK_LENGTH_PENALTY_SIZE (3)
  - FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE (3)
  - FETCHMOPT_MAXCONNECTS (3)
  - FETCHMOPT_MAX_HOST_CONNECTIONS (3)
  - FETCHMOPT_MAX_PIPELINE_LENGTH (3)
  - FETCHMOPT_PIPELINING_SITE_BL (3)
Protocol:
  - HTTP
Added-in: 7.16.0
---

# NAME

FETCHMOPT_PIPELINING - enable HTTP multiplexing

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_PIPELINING, long bitmask);
~~~

# DESCRIPTION

Pass in the correct value in the **bitmask** parameter to instruct libfetch to
enable multiplexing for this multi handle.

With multiplexing enabled, libfetch attempts to do multiple transfers over the
same connection when doing parallel transfers to the same hosts.

## FETCHPIPE_NOTHING (0)

Make no attempts at multiplexing.

## FETCHPIPE_HTTP1 (1)

This bit is deprecated and has no effect since version 7.62.0.

## FETCHPIPE_MULTIPLEX (2)

If this bit is set, libfetch tries to multiplex the new transfer over an
existing connection if possible. This requires HTTP/2 or HTTP/3.

# DEFAULT

**FETCHPIPE_MULTIPLEX**

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *m = fetch_multi_init();
  /* try HTTP/2 multiplexing */
  fetch_multi_setopt(m, FETCHMOPT_PIPELINING, FETCHPIPE_MULTIPLEX);
}
~~~

# HISTORY

The multiplex support bit was added in 7.43.0. HTTP/1 Pipelining support was
disabled in 7.62.0.

Since 7.62.0, **FETCHPIPE_MULTIPLEX** is enabled by default.

Before that, default was **FETCHPIPE_NOTHING**.

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
