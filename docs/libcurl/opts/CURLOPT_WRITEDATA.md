---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_WRITEDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERDATA (3)
  - FETCHOPT_READDATA (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - All
Added-in: 7.9.7
---

# NAME

FETCHOPT_WRITEDATA - pointer passed to the write callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_WRITEDATA, void *pointer);
~~~

# DESCRIPTION

A data *pointer* to pass to the write callback. If you use the
FETCHOPT_WRITEFUNCTION(3) option, this is the pointer you get in that
callback's fourth and last argument. If you do not use a write callback, you
must make *pointer* a 'FILE *' (cast to 'void *') as libfetch passes this
to *fwrite(3)* when writing data.

The internal FETCHOPT_WRITEFUNCTION(3) writes the data to the FILE *
given with this option, or to stdout if this option has not been set.

If you are using libfetch as a Windows DLL, you **MUST** use a
FETCHOPT_WRITEFUNCTION(3) if you set this option or you might experience
crashes.

# DEFAULT

stdout

# %PROTOCOLS%

# EXAMPLE

A common technique is to use the write callback to store the incoming data
into a dynamically growing allocated buffer, and then this
FETCHOPT_WRITEDATA(3) is used to point to a struct or the buffer to store data
in. Like in the getinmemory example:
https://fetch.se/libfetch/c/getinmemory.html

# HISTORY

This option was formerly known as FETCHOPT_FILE, the name FETCHOPT_WRITEDATA(3)
was added in 7.9.7.

# %AVAILABILITY%

# RETURN VALUE

This returns FETCHE_OK.
