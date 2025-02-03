---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TRAILERDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TRAILERFUNCTION (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - HTTP
Added-in: 7.64.0
---

# NAME

FETCHOPT_TRAILERDATA - pointer passed to trailing headers callback

# SYNOPSIS

~~~c
#include <fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TRAILERDATA, void *userdata);
~~~

# DESCRIPTION

Data pointer to be passed to the HTTP trailer callback function.

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
  if(fetch) {
    struct MyData data;
    fetch_easy_setopt(fetch, FETCHOPT_TRAILERDATA, &data);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
