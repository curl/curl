---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_perform
Section: 3
Source: libfetch
See-also:
  - fetch_easy_init (3)
  - fetch_easy_setopt (3)
  - fetch_multi_add_handle (3)
  - fetch_multi_perform (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_easy_perform - perform a blocking network transfer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_perform(FETCH *easy_handle);
~~~

# DESCRIPTION

fetch_easy_perform(3) performs a network transfer in a blocking manner and
returns when done, or earlier if it fails. For non-blocking behavior, see
fetch_multi_perform(3).

Invoke this function after fetch_easy_init(3) and all the fetch_easy_setopt(3)
calls are made, and it performs the transfer as described in the options. It
must be called with the same **easy_handle** as input as the fetch_easy_init(3)
call returned.

You can do any amount of calls to fetch_easy_perform(3) while using the same
**easy_handle**. If you intend to transfer more than one file, you are even
encouraged to do so. libfetch attempts to reuse existing connections for the
following transfers, thus making the operations faster, less CPU intense and
using less network resources. You probably want to use fetch_easy_setopt(3)
between the invokes to set options for the following fetch_easy_perform(3)
call.

You must never call this function simultaneously from two places using the
same **easy_handle**. Let the function return first before invoking it another
time. If you want parallel transfers, you must use several fetch easy_handles.

A network transfer moves data to a peer or from a peer. An application tells
libfetch how to receive data by setting the FETCHOPT_WRITEFUNCTION(3) and
FETCHOPT_WRITEDATA(3) options. To tell libfetch what data to send, there are a
few more alternatives but two common ones are FETCHOPT_READFUNCTION(3) and
FETCHOPT_POSTFIELDS(3).

While the **easy_handle** is added to a multi handle, it cannot be used by
fetch_easy_perform(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
