---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_getenv
Section: 3
Source: libcurl
See-also:
  - getenv (3C)
---

# NAME

curl_getenv - return value for environment name

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_getenv(const char *name);
~~~

# DESCRIPTION

curl_getenv() is a portable wrapper for the getenv() function, meant to
emulate its behavior and provide an identical interface for all operating
systems libcurl builds on (including win32).

You must curl_free(3) the returned string when you are done with it.

# EXAMPLE

~~~c
int main(void)
{
  char *width = curl_getenv("COLUMNS");
  if(width) {
    /* it was set! */
    curl_free(width);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

A pointer to a null-terminated string or NULL if it failed to find the
specified name.

# NOTE

Under unix operating systems, there is no point in returning an allocated
memory, although other systems does not work properly if this is not done. The
unix implementation thus suffers slightly from the drawbacks of other systems.
