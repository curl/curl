---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_strequal
Section: 3
Source: libcurl
See-also:
  - strcasecmp (3)
  - strcmp (3)
Protocol:
  - All
---

# NAME

curl_strequal, curl_strnequal - case insensitive string comparisons

# SYNOPSIS

~~~c
#include <curl/curl.h>

int curl_strequal(const char *str1, const char *str2);
int curl_strnequal(const char *str1, const char *str2, size_t length);
~~~

# DESCRIPTION

The curl_strequal(3) function compares the two strings *str1* and
*str2*, ignoring the case of the characters. It returns a non-zero (TRUE)
integer if the strings are identical.

The **curl_strnequal()** function is similar, except it only compares the
first *length* characters of *str1*.

These functions are provided by libcurl to enable applications to compare
strings in a truly portable manner. There are no standard portable case
insensitive string comparison functions. These two work on all platforms.

# EXAMPLE

~~~c
int main(int argc, char **argv)
{
  const char *name = "compare";
  if(curl_strequal(name, argv[1]))
    printf("Name and input matches\n");
  if(curl_strnequal(name, argv[1], 5))
    printf("Name and input matches in the 5 first bytes\n");
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Non-zero if the strings are identical. Zero if they are not.
