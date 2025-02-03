---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_LOGIN_OPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_USERNAME (3)
Protocol:
  - IMAP
  - LDAP
  - POP3
  - SMTP
Added-in: 7.34.0
---

# NAME

FETCHOPT_LOGIN_OPTIONS - login options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_LOGIN_OPTIONS, char *options);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated *options* string to use for the transfer.

For more information about the login options please see RFC 2384, RFC 5092 and
the IETF draft **draft-earhart-url-smtp-00.txt**.

FETCHOPT_LOGIN_OPTIONS(3) can be used to set protocol specific login options,
such as the preferred authentication mechanism via "AUTH=NTLM" or "AUTH=*",
and should be used in conjunction with the FETCHOPT_USERNAME(3) option.

Since 8.2.0, IMAP supports the login option "AUTH=+LOGIN". With this option,
fetch uses the plain (not SASL) LOGIN IMAP command even if the server
advertises SASL authentication. Care should be taken in using this option, as
it sends your password in plain text. This does not work if the IMAP server
disables the plain LOGIN (e.g. to prevent password snooping).

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_LOGIN_OPTIONS, "AUTH=*");
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
