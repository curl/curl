---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_escape
Section: 3
Source: libcurl
See-also:
  - curl_free (3)
  - curl_unescape (3)
---

# NAME

curl_escape - URL encodes the given string

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_escape(const char *string, int length);
~~~

# DESCRIPTION

Obsolete function. Use curl_easy_escape(3) instead!

This function converts the given input **string** to a URL encoded string
and return that as a new allocated string. All input characters that are not
a-z, A-Z or 0-9 are converted to their "URL escaped" version (**%NN** where
**NN** is a two-digit hexadecimal number).

If the **length** argument is set to 0, curl_escape(3) uses strlen()
on **string** to find out the size.

You must curl_free(3) the returned string when you are done with it.

# EXAMPLE

~~~c
int main(void)
{
  char *output = curl_escape("data to convert", 15);
  if(output) {
    printf("Encoded: %s\n", output);
    curl_free(output);
  }
}
~~~

# AVAILABILITY

Since 7.15.4, curl_easy_escape(3) should be used. This function might be
removed in a future release.

# RETURN VALUE

A pointer to a null-terminated string or NULL if it failed.
