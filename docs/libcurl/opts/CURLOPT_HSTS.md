---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HSTS
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_ALTSVC (3)
  - CURLOPT_HSTS_CTRL (3)
  - CURLOPT_RESOLVE (3)
---

# NAME

CURLOPT_HSTS - HSTS cache filename

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HSTS, char *filename);
~~~

# DESCRIPTION

Make the *filename* point to a filename to load an existing HSTS cache
from, and to store the cache in when the easy handle is closed. Setting a file
name with this option also enables HSTS for this handle (the equivalent of
setting *CURLHSTS_ENABLE* with CURLOPT_HSTS_CTRL(3)).

If the given file does not exist or contains no HSTS entries at startup, the
HSTS cache simply starts empty. Setting the filename to NULL or "" only
enables HSTS without reading from or writing to any file.

If this option is set multiple times, libcurl loads cache entries from each
given file but only stores the last used name for later writing.

# FILE FORMAT

The HSTS cache is saved to and loaded from a text file with one entry per
physical line. Each line in the file has the following format:

[host] [stamp]

[host] is the domain name for the entry and the name is dot-prefixed if it is
an entry valid for all subdomains to the name as well or only for the exact
name.

[stamp] is the time (in UTC) when the entry expires and it uses the format
"YYYYMMDD HH:MM:SS".

Lines starting with "#" are treated as comments and are ignored. There is
currently no length or size limit.

# DEFAULT

NULL, no filename

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_HSTS, "/home/user/.hsts-cache");
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.74.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
