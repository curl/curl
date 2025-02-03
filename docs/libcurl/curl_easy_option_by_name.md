---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_option_by_name
Section: 3
Source: libfetch
See-also:
  - fetch_easy_option_by_id (3)
  - fetch_easy_option_next (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.73.0
---

# NAME

fetch_easy_option_by_name - find an easy setopt option by name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const struct fetch_easyoption *fetch_easy_option_by_name(const char *name);
~~~

# DESCRIPTION

Given a **name**, this function returns a pointer to the
*fetch_easyoption* struct, holding information about the
fetch_easy_setopt(3) option using that name. The name should be specified
without the "FETCHOPT_" prefix and the name comparison is made case
insensitive.

If libfetch has no option with the given name, this function returns NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  const struct fetch_easyoption *opt = fetch_easy_option_by_name("URL");
  if(opt) {
    printf("This option wants FETCHoption %x\n", (int)opt->id);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to the *fetch_easyoption* struct for the option or NULL.
