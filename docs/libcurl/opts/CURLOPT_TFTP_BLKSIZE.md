---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TFTP_BLKSIZE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAXFILESIZE (3)
Protocol:
  - TFTP
Added-in: 7.19.4
---

# NAME

FETCHOPT_TFTP_BLKSIZE - TFTP block size

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TFTP_BLKSIZE, long blocksize);
~~~

# DESCRIPTION

Specify *blocksize* to use for TFTP data transmission. Valid range as per
RFC 2348 is 8-65464 bytes. The default of 512 bytes is used if this option is
not specified. The specified block size is only used if supported by the
remote server. If the server does not return an option acknowledgment or
returns an option acknowledgment with no block size, the default of 512 bytes
is used.

# DEFAULT

512

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "tftp://example.com/bootimage");
    /* try using larger blocks */
    fetch_easy_setopt(fetch, FETCHOPT_TFTP_BLKSIZE, 2048L);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
