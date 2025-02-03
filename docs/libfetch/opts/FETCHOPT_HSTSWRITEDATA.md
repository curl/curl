---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HSTSWRITEDATA
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HSTS (3)
  - FETCHOPT_HSTSREADDATA (3)
  - FETCHOPT_HSTSREADFUNCTION (3)
  - FETCHOPT_HSTSWRITEFUNCTION (3)
Added-in: 7.74.0
---

# NAME

FETCHOPT_HSTSWRITEDATA - pointer passed to the HSTS write callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HSTSWRITEDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the HSTS write function. If you use the
FETCHOPT_HSTSWRITEFUNCTION(3) option, this is the pointer you get as
input in the fourth argument to the callback.

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
       FETCHOPT_HSTSWRITEFUNCTION callback */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSWRITEDATA, &this);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
