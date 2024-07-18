---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_USERNAME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPAUTH (3)
  - CURLOPT_PASSWORD (3)
  - CURLOPT_PROXYAUTH (3)
  - CURLOPT_USERPWD (3)
Protocol:
  - All
Added-in: 7.19.1
---

# NAME

CURLOPT_USERNAME - username to use in authentication

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_USERNAME,
                          char *username);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated username to use for the transfer.

CURLOPT_USERNAME(3) sets the username to be used in protocol
authentication. You should not use this option together with the (older)
CURLOPT_USERPWD(3) option.

When using Kerberos V5 authentication with a Windows based server, you should
include the domain name in order for the server to successfully obtain a
Kerberos Ticket. If you do not then the initial part of the authentication
handshake may fail.

When using NTLM, the username can be specified simply as the username without
the domain name should the server be part of a single domain and forest.

To include the domain name use either Down-Level Logon Name or UPN (User
Principal Name) formats. For example, **EXAMPLE\user** and
**user@example.com** respectively.

Some HTTP servers (on Windows) support inclusion of the domain for Basic
authentication as well.

To specify the password and login options, along with the username, use the
CURLOPT_PASSWORD(3) and CURLOPT_LOGIN_OPTIONS(3) options.

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
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    curl_easy_setopt(curl, CURLOPT_USERNAME, "clark");

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, CURLE_UNKNOWN_OPTION if not, or
CURLE_OUT_OF_MEMORY if there was insufficient heap space.
