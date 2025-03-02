---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_WRITEDATA
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERDATA (3)
  - CURLOPT_READDATA (3)
  - CURLOPT_WRITEFUNCTION (3)
Protocol:
  - All
Added-in: 7.9.7
---

# NAME

CURLOPT_WRITEDATA - pointer passed to the write callback

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_WRITEDATA, void *pointer);
~~~

# DESCRIPTION

A data *pointer* to pass to the write callback. If you use the
CURLOPT_WRITEFUNCTION(3) option, this is the pointer you get in that
callback's fourth and last argument. If you do not use a write callback, you
must make *pointer* a 'FILE *' (cast to 'void *') as libcurl passes this
to *fwrite(3)* when writing data.

The internal CURLOPT_WRITEFUNCTION(3) writes the data to the FILE *
given with this option, or to stdout if this option has not been set.

If you are using libcurl as a Windows DLL, you **MUST** use a
CURLOPT_WRITEFUNCTION(3) if you set this option or you might experience
crashes.

# DEFAULT

stdout

# %PROTOCOLS%

# EXAMPLE

A common technique is to use the write callback to store the incoming data
into a dynamically growing allocated buffer, and then this
CURLOPT_WRITEDATA(3) is used to point to a struct or the buffer to store data
in. Like in the *getinmemory* example:
https://curl.se/libcurl/c/getinmemory.html

# HISTORY

This option was formerly known as CURLOPT_FILE, the name CURLOPT_WRITEDATA(3)
was added in 7.9.7.

# %AVAILABILITY%

# RETURN VALUE

This returns CURLE_OK.
