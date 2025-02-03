---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TELNETOPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_QUOTE (3)
Protocol:
  - TELNET
Added-in: 7.7
---

# NAME

FETCHOPT_TELNETOPTIONS - set of telnet options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TELNETOPTIONS,
                          struct fetch_slist *cmds);
~~~

# DESCRIPTION

Provide a pointer to a fetch_slist with variables to pass to the telnet
negotiations. The variables should be in the format \<option=value\>. libfetch
supports the options **TTYPE**, **XDISPLOC** and **NEW_ENV**. See the TELNET
standard for details.

Using this option multiple times makes the last set list override the previous
ones. Set it to NULL to disable its use again.

libfetch does not copy the list, it needs to be kept around until after the
transfer has completed.

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
    struct fetch_slist *options;
    options = fetch_slist_append(NULL, "TTTYPE=vt100");
    options = fetch_slist_append(options, "USER=foobar");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "telnet://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_TELNETOPTIONS, options);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
    fetch_slist_free_all(options);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
