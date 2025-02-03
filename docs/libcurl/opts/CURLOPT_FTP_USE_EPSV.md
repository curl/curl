---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_USE_EPSV
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_FTPPORT (3)
  - FETCHOPT_FTP_USE_EPRT (3)
Added-in: 7.9.2
---

# NAME

FETCHOPT_FTP_USE_EPSV - use EPSV for FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_USE_EPSV, long epsv);
~~~

# DESCRIPTION

Pass *epsv* as a long. If the value is 1, it tells fetch to use the EPSV
command when doing passive FTP downloads (which it does by default). Using
EPSV means that libfetch first attempts to use the EPSV command before using
PASV. If you pass zero to this option, it does not use EPSV, only plain PASV.

The EPSV command is a slightly newer addition to the FTP protocol than PASV
and is the preferred command to use since it enables IPv6 to be used. Old FTP
servers might not support it, which is why libfetch has a fallback mechanism.
Sometimes that fallback is not enough and then this option might come handy.

If the server is an IPv6 host, this option has no effect.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://example.com/old-server/file.txt");

    /* let's shut off this modern feature */
    fetch_easy_setopt(fetch, FETCHOPT_FTP_USE_EPSV, 0L);

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
