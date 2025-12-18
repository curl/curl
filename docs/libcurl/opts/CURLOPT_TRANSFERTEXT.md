---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TRANSFERTEXT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CRLF (3)
Protocol:
  - All
Added-in: 7.1.1
---

# NAME

CURLOPT_TRANSFERTEXT - request a text based transfer for FTP

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TRANSFERTEXT, long text);
~~~

# DESCRIPTION

A parameter set to 1 tells the library to use ASCII mode for FTP transfers,
instead of the default binary transfer. For Win32 systems it does not set the
stdout to binary mode. This option can be usable when transferring text data
between systems with different views on certain characters, such as newlines
or similar.

libcurl does not do a complete ASCII conversion when doing ASCII transfers
over FTP. This is a known limitation/flaw that nobody has rectified. libcurl
simply sets the mode to ASCII and performs a standard transfer.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/textfile");
    curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
