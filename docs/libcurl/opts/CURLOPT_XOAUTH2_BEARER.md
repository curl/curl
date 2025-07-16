---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_XOAUTH2_BEARER
Section: 3
Source: libcurl
See-also:
  - CURLOPT_MAIL_AUTH (3)
  - CURLOPT_USERNAME (3)
Protocol:
  - HTTP
  - IMAP
  - LDAP
  - POP3
  - SMTP
Added-in: 7.33.0
---

# NAME

CURLOPT_XOAUTH2_BEARER - OAuth 2.0 access token

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_XOAUTH2_BEARER, char *token);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
OAuth 2.0 Bearer Access Token for use with HTTP, IMAP, LDAP, POP3 and SMTP
servers that support the OAuth 2.0 Authorization Framework.

Note: For IMAP, LDAP, POP3 and SMTP, the username used to generate the Bearer
Token should be supplied via the CURLOPT_USERNAME(3) option.

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
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "pop3://example.com/");
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, "1ab9cb22bf269a7");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# HISTORY

Support for OpenLDAP added in 7.82.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
