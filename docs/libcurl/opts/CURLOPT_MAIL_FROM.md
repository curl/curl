---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAIL_FROM
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAIL_AUTH (3)
  - CURLOPT_MAIL_RCPT (3)
Protocol:
  - SMTP
Added-in: 7.20.0
---

# NAME

CURLOPT_MAIL_FROM - SMTP sender address

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAIL_FROM, char *from);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. This should be used
to specify the sender's email address when sending SMTP mail with libcurl.

An originator email address should be specified with angled brackets (\<\>)
around it, which if not specified are added automatically.

If this parameter is not specified then an empty address is sent to the SMTP
server which might cause the email to be rejected.

The application does not have to keep the string around after setting this
option.

# DEFAULT

blank

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://example.com/");
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "president@example.com");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
