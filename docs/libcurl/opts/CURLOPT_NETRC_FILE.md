---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NETRC_FILE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_NETRC (3)
  - CURLOPT_PASSWORD (3)
  - CURLOPT_USERNAME (3)
Protocol:
  - All
Added-in: 7.11.0
---

# NAME

CURLOPT_NETRC_FILE - filename to read .netrc info from

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NETRC_FILE, char *file);
~~~

# DESCRIPTION

Pass a char pointer as parameter, pointing to a null-terminated string
containing the full path name to the *file* you want libcurl to use as .netrc
file. If this option is omitted, and CURLOPT_NETRC(3) is set, libcurl checks
for a .netrc file in the current user's home directory.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "ftp://example.com/");
    curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);
    curl_easy_setopt(curl, CURLOPT_NETRC_FILE, "/tmp/magic-netrc");
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
