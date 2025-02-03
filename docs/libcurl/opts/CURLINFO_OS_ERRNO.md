---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_OS_ERRNO
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.12.2
---

# NAME

FETCHINFO_OS_ERRNO - get errno number from last connect failure

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_OS_ERRNO, long *errnop);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the errno variable from a connect failure.
Note that the value is only set on failure, it is not reset upon a successful
operation. The number is OS and system specific.

libfetch network-related errors that may have a saved errno are:
FETCHE_COULDNT_CONNECT, FETCHE_FAILED_INIT, FETCHE_INTERFACE_FAILED,
FETCHE_OPERATION_TIMEDOUT, FETCHE_RECV_ERROR, FETCHE_SEND_ERROR.

Since 8.8.0 libfetch clears the easy handle's saved errno before performing the
transfer. Prior versions did not clear the saved errno, which means if a saved
errno is retrieved it could be from a previous transfer on the same handle.

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
    if(res != FETCHE_OK) {
      long error;
      res = fetch_easy_getinfo(fetch, FETCHINFO_OS_ERRNO, &error);
      if(!res && error) {
        printf("Errno: %ld\n", error);
      }
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
