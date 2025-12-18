---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_KEEP_SENDING_ON_ERROR
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RESPONSE_CODE (3)
  - CURLOPT_FAILONERROR (3)
  - CURLOPT_HTTPHEADER (3)
Protocol:
  - HTTP
Added-in: 7.51.0
---

# NAME

CURLOPT_KEEP_SENDING_ON_ERROR - keep sending on early HTTP response \>= 300

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_KEEP_SENDING_ON_ERROR,
                          long keep_sending);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to keep sending the request body
if the HTTP code returned is equal to or larger than 300. The default action
would be to stop sending and close the stream or connection.

This option is suitable for manual NTLM authentication, i.e. if an application
does not use CURLOPT_HTTPAUTH(3), but instead sets "Authorization: NTLM ..."
headers manually using CURLOPT_HTTPHEADER(3).

Most applications do not need this option.

# DEFAULT

0, stop sending on error

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "sending data");
    curl_easy_setopt(curl, CURLOPT_KEEP_SENDING_ON_ERROR, 1L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
