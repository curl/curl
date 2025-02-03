---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HSTSREADDATA
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HSTS (3)
  - FETCHOPT_HSTSREADFUNCTION (3)
  - FETCHOPT_HSTSWRITEDATA (3)
  - FETCHOPT_HSTSWRITEFUNCTION (3)
Added-in: 7.74.0
---

# NAME

FETCHOPT_HSTSREADDATA - pointer passed to the HSTS read callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HSTSREADDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the HSTS read function. If you use the
FETCHOPT_HSTSREADFUNCTION(3) option, this is the pointer you get as input
in the 3rd argument to the callback.

This option does not enable HSTS, you need to use FETCHOPT_HSTS_CTRL(3) to
do that.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct MyData {
  void *custom;
};

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  struct MyData this;
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://example.com");

    /* pass pointer that gets passed in to the
       FETCHOPT_HSTSREADFUNCTION callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSREADDATA, &this);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
