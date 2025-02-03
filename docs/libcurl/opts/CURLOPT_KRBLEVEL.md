---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_KRBLEVEL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_KRBLEVEL (3)
  - FETCHOPT_USE_SSL (3)
Protocol:
  - FTP
Added-in: 7.16.4
---

# NAME

FETCHOPT_KRBLEVEL - FTP kerberos security level

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_KRBLEVEL, char *level);
~~~

# DESCRIPTION

Pass a char pointer as parameter. Set the kerberos security level for FTP;
this also enables kerberos awareness. This is a string that should match one
of the following: &'clear', &'safe', &'confidential' or &'private'. If the
string is set but does not match one of these, 'private' is used. Set the
string to NULL to disable kerberos support for FTP.

The application does not have to keep the string around after setting this
option.

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_KRBLEVEL, "private");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_KRB4LEVEL up to 7.16.3

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
