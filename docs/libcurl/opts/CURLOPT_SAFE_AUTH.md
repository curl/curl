---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SAFE_AUTH
Section: 3
Source: "libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_LOGIN_OPTIONS (3)
Protocol:
  - FTP
  - HTTP
  . IMAP
  - LDAP
  - POP3
  - SMTP
---

# NAME

CURLOPT_SAFE_AUTH - do not use clear password authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SAFE_AUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long that holds a bitmask of CURLSAFE_* defines. Each bit is a Boolean
flag disabling unsafe authentication mechanisms for a particular target.
When set, a bit rejects authentication mechanisms that would
transfer clear passwords on a non-encrypted connection.

Available bits are:

## CURLSAFE_AUTH

Disable unsafe authentication mechanisms with the target server.

## CURLSAFE_PROXYAUTH

Disable unsafe authentication mechanisms with the proxy server.

These disabling bits have precedence over mechanisms selected by other options.

# DEFAULT

0: allow all uses of unsafe authentication mechanisms.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "http://user:password@example.com/");
    curl_easy_setopt(curl, CURLOPT_SAFE_AUTH, CURLSAFE_AUTH);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
  return 0;
}
~~~

# AVAILABILITY

Added in 8.xx.x

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
