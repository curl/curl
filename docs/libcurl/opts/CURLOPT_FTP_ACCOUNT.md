---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_ACCOUNT
Section: 3
Source: libfetch
Protocol:
  - FTP
See-also:
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_USERNAME (3)
Added-in: 7.13.0
---

# NAME

FETCHOPT_FTP_ACCOUNT - account info for FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_ACCOUNT, char *account);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string (or NULL to disable). When an FTP
server asks for "account data" after username and password has been provided,
this data is sent off using the ACCT command.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/foo.bin");

    fetch_easy_setopt(fetch, FETCHOPT_FTP_ACCOUNT, "human-resources");

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
