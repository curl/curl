---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_strnequal
Section: 3
Source: libcurl
See-also:
  - curl_strequal (3)
  - strcasecmp (3)
  - strcmp (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

curl_strnequal - compare two strings ignoring case

# SYNOPSIS

~~~c
#include <curl/curl.h>

int curl_strnequal(const char *str1, const char *str2, size_t length);
~~~

# DESCRIPTION

The curl_strnequal(3) function compares the two strings *str1* and *str2*,
ignoring the case of the characters. It returns a non-zero (TRUE) integer if
the strings are identical.

This function compares no more than the first *length* bytes of *str1* and
*str2*.

This function uses plain ASCII based comparisons completely disregarding the
locale - contrary to how **strcasecmp** and other system case insensitive
string comparisons usually work.

This function is provided by libcurl to enable applications to compare strings
in a truly portable manner. There are no standard portable case insensitive
string comparison functions. This function works on all platforms.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  const char *name = "compare";
  if(curl_strnequal(name, argv[1], 5))
    printf("Name and input matches in the 5 first bytes\n");
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Non-zero if the strings are identical. Zero if they are not.
