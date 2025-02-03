---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_PIPELINING_SITE_BL
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PIPELINING (3)
  - FETCHMOPT_PIPELINING_SERVER_BL (3)
Protocol:
  - HTTP
Added-in: 7.30.0
---

# NAME

FETCHMOPT_PIPELINING_SITE_BL - pipelining host block list

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_PIPELINING_SITE_BL,
                            char **hosts);
~~~

# DESCRIPTION

No function since pipelining was removed in 7.62.0.

Pass a **hosts** array of char *, ending with a NULL entry. This is a list
of sites that are blocked from pipelining, i.e sites that are known to not
support HTTP pipelining. The array is copied by libfetch.

Pass a NULL pointer to clear the block list.

# DEFAULT

NULL, which means that there is no block list.

# %PROTOCOLS%

# EXAMPLE

~~~c
static char *site_block_list[] =
{
  "www.haxx.se",
  "www.example.com:1234",
  NULL
};

int main(void)
{
  FETCHM *m = fetch_multi_init();
  fetch_multi_setopt(m, FETCHMOPT_PIPELINING_SITE_BL, site_block_list);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
