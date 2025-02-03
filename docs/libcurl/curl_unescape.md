---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_unescape
Section: 3
Source: libfetch
See-also:
  - RFC 2396
  - fetch_easy_escape (3)
  - fetch_easy_unescape (3)
  - fetch_free (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_unescape - URL decode a string

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_unescape(const char *input, int length);
~~~

# DESCRIPTION

Deprecated. Use fetch_easy_unescape(3) instead.

This function converts the URL encoded string **input** to a "plain string"
and return that as a new allocated string. All input characters that are URL
encoded (%XX where XX is a two-digit hexadecimal number) are converted to
their plain text versions.

If the **length** argument is set to 0, fetch_unescape(3) calls
strlen() on **input** to find out the size.

You must fetch_free(3) the returned string when you are done with it.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    char *decoded = fetch_unescape("%63%75%72%6c", 12);
    if(decoded) {
      /* do not assume printf() works on the decoded data */
      printf("Decoded: ");
      /* ... */
      fetch_free(decoded);
    }
  }
}
~~~

# DEPRECATED

Since 7.15.4, fetch_easy_unescape(3) should be used. This function might
be removed in a future release.

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string or NULL if it failed.
