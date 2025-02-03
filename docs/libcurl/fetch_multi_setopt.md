---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_setopt
Section: 3
Source: libfetch
See-also:
  - fetch_multi_cleanup (3)
  - fetch_multi_info_read (3)
  - fetch_multi_init (3)
  - fetch_multi_socket (3)
Protocol:
  - All
Added-in: 7.15.4
---

# NAME

fetch_multi_setopt - set options for a fetch multi handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *multi, FETCHMoption option, parameter);
~~~

# DESCRIPTION

fetch_multi_setopt(3) is used to tell a libfetch multi handle how to behave. By
using the appropriate options to fetch_multi_setopt(3), you can change
libfetch's behavior when using that multi handle. All options are set with the
*option* followed by the *parameter*. That parameter can be a **long**, a
**function pointer**, an **object pointer** or a **fetch_off_t** type,
depending on what the specific option expects. Read this manual carefully as
bad input values may cause libfetch to behave badly. You can only set one
option in each function call.

# OPTIONS

## FETCHMOPT_CHUNK_LENGTH_PENALTY_SIZE

**deprecated** See FETCHMOPT_CHUNK_LENGTH_PENALTY_SIZE(3)

## FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE

**deprecated** See FETCHMOPT_CONTENT_LENGTH_PENALTY_SIZE(3)

## FETCHMOPT_MAXCONNECTS

Size of connection cache. See FETCHMOPT_MAXCONNECTS(3)

## FETCHMOPT_MAX_CONCURRENT_STREAMS

Max concurrent streams for http2. See FETCHMOPT_MAX_CONCURRENT_STREAMS(3)

## FETCHMOPT_MAX_HOST_CONNECTIONS

Max number of connections to a single host. See
FETCHMOPT_MAX_HOST_CONNECTIONS(3)

## FETCHMOPT_MAX_PIPELINE_LENGTH

**deprecated**. See FETCHMOPT_MAX_PIPELINE_LENGTH(3)

## FETCHMOPT_MAX_TOTAL_CONNECTIONS

Max simultaneously open connections. See FETCHMOPT_MAX_TOTAL_CONNECTIONS(3)

## FETCHMOPT_PIPELINING

Enable HTTP multiplexing. See FETCHMOPT_PIPELINING(3)

## FETCHMOPT_PIPELINING_SERVER_BL

**deprecated**. See FETCHMOPT_PIPELINING_SERVER_BL(3)

## FETCHMOPT_PIPELINING_SITE_BL

**deprecated**. See FETCHMOPT_PIPELINING_SITE_BL(3)

## FETCHMOPT_PUSHDATA

Pointer to pass to push callback. See FETCHMOPT_PUSHDATA(3)

## FETCHMOPT_PUSHFUNCTION

Callback that approves or denies server pushes. See FETCHMOPT_PUSHFUNCTION(3)

## FETCHMOPT_SOCKETDATA

Custom pointer passed to the socket callback. See FETCHMOPT_SOCKETDATA(3)

## FETCHMOPT_SOCKETFUNCTION

Callback informed about what to wait for. See FETCHMOPT_SOCKETFUNCTION(3)

## FETCHMOPT_TIMERDATA

Custom pointer to pass to timer callback. See FETCHMOPT_TIMERDATA(3)

## FETCHMOPT_TIMERFUNCTION

Callback to receive timeout values. See FETCHMOPT_TIMERFUNCTION(3)

# %PROTOCOLS%

# EXAMPLE

~~~c

#define MAX_PARALLEL 45

int main(void)
{
  FETCHM *multi;
  /* Limit the amount of simultaneous connections fetch should allow: */
  fetch_multi_setopt(multi, FETCHMOPT_MAXCONNECTS, (long)MAX_PARALLEL);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).

Note that it returns a FETCHM_UNKNOWN_OPTION if you try setting an option that
this version of libfetch does not know of.
