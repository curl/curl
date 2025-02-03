---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_option_by_id
Section: 3
Source: libfetch
See-also:
  - fetch_easy_option_by_name (3)
  - fetch_easy_option_next (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

fetch_easy_option_by_id - find an easy setopt option by id

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const struct fetch_easyoption *fetch_easy_option_by_id(FETCHoption id);
~~~

# DESCRIPTION

Given a *FETCHoption* **id**, this function returns a pointer to the
*fetch_easyoption* struct, holding information about the
fetch_easy_setopt(3) option using that id. The option id is the FETCHOPT_
prefix ones provided in the standard fetch/fetch.h header file. This function
returns the non-alias version of the cases where there is an alias function as
well.

If libfetch has no option with the given id, this function returns NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  const struct fetch_easyoption *opt = fetch_easy_option_by_id(FETCHOPT_URL);
  if(opt) {
    printf("This option wants type %x\n", opt->type);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to the *fetch_easyoption* struct for the option or NULL.
