---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_unescape
Section: 3
Source: libcurl
See-also:
  - RFC 2396
  - curl_easy_escape (3)
  - curl_easy_unescape (3)
  - curl_free (3)
Protocol:
  - All
---

# NAME

curl_unescape - URL decodes the given string

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_unescape(const char *input, int length);
~~~

# DESCRIPTION

Obsolete function. Use curl_easy_unescape(3) instead.

This function converts the URL encoded string **input** to a "plain string"
and return that as a new allocated string. All input characters that are URL
encoded (%XX where XX is a two-digit hexadecimal number) are converted to
their plain text versions.

If the **length** argument is set to 0, curl_unescape(3) calls
strlen() on **input** to find out the size.

You must curl_free(3) the returned string when you are done with it.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    char *decoded = curl_unescape("%63%75%72%6c", 12);
    if(decoded) {
      /* do not assume printf() works on the decoded data */
      printf("Decoded: ");
      /* ... */
      curl_free(decoded);
    }
  }
}
~~~

# AVAILABILITY

Since 7.15.4, curl_easy_unescape(3) should be used. This function might
be removed in a future release.

# RETURN VALUE

A pointer to a null-terminated string or NULL if it failed.
