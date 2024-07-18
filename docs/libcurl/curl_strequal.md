---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_strequal
Section: 3
Source: libcurl
See-also:
  - curl_strnequal (3)
  - strcasecmp (3)
  - strcmp (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

curl_strequal - compare two strings ignoring case

# SYNOPSIS

~~~c
#include <curl/curl.h>

int curl_strequal(const char *str1, const char *str2);
~~~

# DESCRIPTION

The curl_strequal(3) function compares the two strings *str1* and *str2*,
ignoring the case of the characters. It returns a non-zero (TRUE) integer if
the strings are identical.

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
  if(curl_strequal(name, argv[1]))
    printf("Name and input matches\n");
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Non-zero if the strings are identical. Zero if they are not.
