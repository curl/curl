---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_KRBLEVEL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_USE_SSL (3)
Protocol:
  - FTP
Added-in: 7.16.4
---

# NAME

CURLOPT_KRBLEVEL - FTP kerberos security level

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_KRBLEVEL, char *level);
~~~

# DESCRIPTION

Deprecated. It serves no purpose anymore.

Pass a char pointer as parameter. Set the kerberos security level for FTP;
this also enables kerberos awareness. This is a string that should match one
of the following: `clear`, `safe`, `confidential` or `private`. If the string
is set but does not match one of these, `private` is used. Set the string to
NULL to disable kerberos support for FTP.

The application does not have to keep the string around after setting this
option.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/foo.bin");
    curl_easy_setopt(curl, CURLOPT_KRBLEVEL, "private");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

Functionality removed in 8.17.0

This option was known as CURLOPT_KRB4LEVEL up to 7.16.3

# DEPRECATED

Deprecated since 8.17.0

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
