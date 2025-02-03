---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_READDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERDATA (3)
  - FETCHOPT_READFUNCTION (3)
  - FETCHOPT_WRITEDATA (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - All
Added-in: 7.9.7
---

# NAME

FETCHOPT_READDATA - pointer passed to the read callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_READDATA, void *pointer);
~~~

# DESCRIPTION

Data *pointer* to pass to the file read function. If you use the
FETCHOPT_READFUNCTION(3) option, this is the pointer you get as input in
the fourth argument to the callback.

If you do not specify a read callback but instead rely on the default internal
read function, this data must be a valid readable FILE * (cast to 'void *').

If you are using libfetch as a DLL on Windows, you must use the
FETCHOPT_READFUNCTION(3) callback if you set this option, otherwise you
might experience crashes.

# DEFAULT

stdin

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* pass pointer that gets passed in to the
       FETCHOPT_READFUNCTION callback */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, &this);

    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

This option was once known by the older name FETCHOPT_INFILE, the name
FETCHOPT_READDATA(3) was introduced in 7.9.7.

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
