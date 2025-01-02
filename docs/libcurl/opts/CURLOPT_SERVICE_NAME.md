---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SERVICE_NAME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PROXY (3)
  - CURLOPT_PROXYTYPE (3)
  - CURLOPT_PROXY_SERVICE_NAME (3)
Protocol:
  - HTTP
  - FTP
  - IMAP
  - POP3
  - SMTP
  - LDAP
Added-in: 7.43.0
---

# NAME

CURLOPT_SERVICE_NAME - authentication service name

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SERVICE_NAME, char *name);
~~~

# DESCRIPTION

Pass a char pointer as parameter to a string holding the *name* of the service
for DIGEST-MD5, SPNEGO and Kerberos 5 authentication mechanisms. The default
service names are "ftp", "HTTP", "imap", "ldap", "pop" and "smtp". This option
allows you to change them.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

See above

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SERVICE_NAME, "custom");
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
