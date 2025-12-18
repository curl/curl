---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: curl_version
Section: 3
Source: libcurl
See-also:
  - curl_version_info (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

curl_version - returns the libcurl version string

# SYNOPSIS

~~~c
#include <curl/curl.h>

char *curl_version();
~~~

# DESCRIPTION

Returns a human readable string with the version number of libcurl and some of
its important components (like OpenSSL version).

For MultiSSL builds the string contains all SSL backend names and the inactive
backend names are in parentheses. For example "(OpenSSL/3.0.8) Schannel" or
"OpenSSL/3.0.8 (Schannel)".

We recommend using curl_version_info(3) instead.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  printf("libcurl version %s\n", curl_version());
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string. The string resides in a statically
allocated buffer and must not be freed by the caller.
