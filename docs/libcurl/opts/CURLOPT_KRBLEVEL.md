---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_KRBLEVEL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_KRBLEVEL (3)
  - CURLOPT_USE_SSL (3)
---

# NAME

CURLOPT_KRBLEVEL - FTP kerberos security level

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_KRBLEVEL, char *level);
~~~

# DESCRIPTION

Pass a char pointer as parameter. Set the kerberos security level for FTP;
this also enables kerberos awareness. This is a string that should match one
of the following: &'clear', &'safe', &'confidential' or &'private'. If the
string is set but does not match one of these, 'private' is used. Set the
string to NULL to disable kerberos support for FTP.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# PROTOCOLS

FTP

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

# AVAILABILITY

This option was known as CURLOPT_KRB4LEVEL up to 7.16.3

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
