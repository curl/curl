---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SASL_AUTHZID
Section: 3
Source: libcurl
See-also:
  - CURLOPT_PASSWORD (3)
  - CURLOPT_USERNAME (3)
  - CURLOPT_USERPWD (3)
Protocol:
  - IMAP
Added-in: 7.66.0
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

When not specified only the authentication identity (*authcid*) as specified
by the username is sent to the server, along with the password. The server
derives a *authzid* from the *authcid* when not provided, which it then uses
internally.

When the *authzid* is specified, the use of which is server dependent, it can
be used to access another user's inbox, that the user has been granted access
to, or a shared mailbox for example.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

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
    curl_easy_setopt(curl, CURLOPT_URL, "imap://example.com/");
    curl_easy_setopt(curl, CURLOPT_USERNAME, "Kurt");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "xipj3plmq");
    curl_easy_setopt(curl, CURLOPT_SASL_AUTHZID, "Ursel");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
