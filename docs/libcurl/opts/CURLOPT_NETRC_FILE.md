---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NETRC_FILE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NETRC (3)
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_USERNAME (3)
Protocol:
  - All
Added-in: 7.11.0
---

# NAME

FETCHOPT_NETRC_FILE - filename to read .netrc info from

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NETRC_FILE, char *file);
~~~

# DESCRIPTION

Pass a char pointer as parameter, pointing to a null-terminated string
containing the full path name to the *file* you want libfetch to use as .netrc
file. If this option is omitted, and FETCHOPT_NETRC(3) is set, libfetch checks
for a .netrc file in the current user's home directory.

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
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_NETRC, FETCH_NETRC_OPTIONAL);
    fetch_easy_setopt(fetch, FETCHOPT_NETRC_FILE, "/tmp/magic-netrc");
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
