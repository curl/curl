---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_XOAUTH2_BEARER
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_AUTH (3)
  - FETCHOPT_USERNAME (3)
Protocol:
  - HTTP
  - IMAP
  - LDAP
  - POP3
  - SMTP
Added-in: 7.33.0
---

# NAME

FETCHOPT_XOAUTH2_BEARER - OAuth 2.0 access token

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_XOAUTH2_BEARER, char *token);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should point to the null-terminated
OAuth 2.0 Bearer Access Token for use with HTTP, IMAP, LDAP, POP3 and SMTP
servers that support the OAuth 2.0 Authorization Framework.

Note: For IMAP, LDAP, POP3 and SMTP, the username used to generate the Bearer
Token should be supplied via the FETCHOPT_USERNAME(3) option.

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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "pop3://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_XOAUTH2_BEARER, "1ab9cb22ba269a7");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

Support for OpenLDAP added in 7.82.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
