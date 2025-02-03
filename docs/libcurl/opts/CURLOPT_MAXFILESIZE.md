---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXFILESIZE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAXFILESIZE_LARGE (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
Protocol:
  - All
Added-in: 7.10.8
---

# NAME

FETCHOPT_MAXFILESIZE - maximum file size allowed to download

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXFILESIZE, long size);
~~~

# DESCRIPTION

Pass a long as parameter. This specifies the maximum accepted *size* (in
bytes) of a file to download. If the file requested is found larger than this
value, the transfer is aborted and *FETCHE_FILESIZE_EXCEEDED* is returned.
Passing a zero *size* disables this, and passing a negative *size* yields a
*FETCHE_BAD_FUNCTION_ARGUMENT*.

The file size is not always known prior to the download start, and for such
transfers this option has no effect - even if the file transfer eventually
ends up being larger than this given limit.

If you want a limit above 2GB, use FETCHOPT_MAXFILESIZE_LARGE(3).

Since 8.4.0, this option also stops ongoing transfers if they reach this
threshold.

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* refuse to download if larger than 1000 bytes */
    fetch_easy_setopt(fetch, FETCHOPT_MAXFILESIZE, 1000L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
