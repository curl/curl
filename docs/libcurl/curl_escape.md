---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_escape
Section: 3
Source: libfetch
See-also:
  - fetch_free (3)
  - fetch_unescape (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_escape - URL encode a string

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_escape(const char *string, int length);
~~~

# DESCRIPTION

Obsolete function. Use fetch_easy_escape(3) instead.

This function converts the given input **string** to a URL encoded string
and return that as a new allocated string. All input characters that are not
a-z, A-Z or 0-9 are converted to their "URL escaped" version (**%NN** where
**NN** is a two-digit hexadecimal number).

If the **length** argument is set to 0, fetch_escape(3) uses strlen()
on **string** to find out the size.

You must fetch_free(3) the returned string when you are done with it.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  char *output = fetch_escape("data to convert", 15);
  if(output) {
    printf("Encoded: %s\n", output);
    fetch_free(output);
  }
}
~~~

# HISTORY

Since 7.15.4, fetch_easy_escape(3) should be used. This function might be
removed in a future release.

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string or NULL if it failed.
