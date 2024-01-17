---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_STDERR
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_NOPROGRESS (3)
  - CURLOPT_VERBOSE (3)
---

# NAME

CURLOPT_STDERR - redirect stderr to another stream

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_STDERR, FILE *stream);
~~~

# DESCRIPTION

Pass a FILE * as parameter. Tell libcurl to use this *stream* instead of
stderr when showing the progress meter and displaying CURLOPT_VERBOSE(3)
data.

If you are using libcurl as a Windows DLL, this option causes an exception and
a crash in the library since it cannot access a FILE * passed on from the
application. A work-around is to instead use CURLOPT_DEBUGFUNCTION(3).

# DEFAULT

stderr

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  FILE *filep = fopen("dump", "wb");
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_STDERR, filep);

    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
