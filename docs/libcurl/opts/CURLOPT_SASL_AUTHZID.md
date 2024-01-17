---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SASL_AUTHZID
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PASSWORD (3)
  - CURLOPT_USERNAME (3)
  - CURLOPT_USERPWD (3)
---

# NAME

CURLOPT_SASL_AUTHZID - authorization identity (identity to act as)

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SASL_AUTHZID, char *authzid);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated authorization identity (*authzid*) for the transfer. Only
applicable to the PLAIN SASL authentication mechanism where it is optional.

When not specified only the authentication identity (*authcid*) as
specified by the username is sent to the server, along with the password. The
server derives a *authzid* from the *authcid* when not provided, which
it then uses internally.

When the *authzid* is specified, the use of which is server dependent, it
can be used to access another user's inbox, that the user has been granted
access to, or a shared mailbox for example.

# DEFAULT

blank

# PROTOCOLS

IMAP, LDAP, POP3 and SMTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "imap://example.com/");
    curl_easy_setopt(curl, CURLOPT_USERNAME, "Kurt");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "xipj3plmq");
    curl_easy_setopt(curl, CURLOPT_SASL_AUTHZID, "Ursel");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.66.0. Support for OpenLDAP added in 7.82.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
