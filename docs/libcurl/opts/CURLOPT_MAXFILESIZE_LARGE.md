---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXFILESIZE_LARGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAXFILESIZE (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
Protocol:
  - FTP
  - HTTP
  - MQTT
Added-in: 7.11.0
---

# NAME

FETCHOPT_MAXFILESIZE_LARGE - maximum file size allowed to download

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXFILESIZE_LARGE,
                          fetch_off_t size);
~~~

# DESCRIPTION

Pass a fetch_off_t as parameter. This specifies the maximum accepted *size*
(in bytes) of a file to download. If the file requested is found larger than
this value, the transfer is aborted and *FETCHE_FILESIZE_EXCEEDED* is
returned. Passing a zero *size* disables this, and passing a negative *size*
yields a *FETCHE_BAD_FUNCTION_ARGUMENT*.

The file size is not always known prior to the download start, and for such
transfers this option has no effect - even if the file transfer eventually
ends up being larger than this given limit.

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
    fetch_off_t ridiculous = (fetch_off_t)1 << 48;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* refuse to download if larger than ridiculous */
    fetch_easy_setopt(fetch, FETCHOPT_MAXFILESIZE_LARGE, ridiculous);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
