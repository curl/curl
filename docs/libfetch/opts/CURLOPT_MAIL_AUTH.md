---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAIL_AUTH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_FROM (3)
  - FETCHOPT_MAIL_RCPT (3)
Protocol:
  - SMTP
Added-in: 7.25.0
---

# NAME

FETCHOPT_MAIL_AUTH - SMTP authentication address

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAIL_AUTH, char *auth);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. This is used to
specify the authentication address (identity) of a submitted message that is
being relayed to another server.

This optional parameter allows co-operating agents in a trusted environment to
communicate the authentication of individual messages and should only be used
by the application program, using libfetch, if the application is itself a mail
server acting in such an environment. If the application is operating as such
and the AUTH address is not known or is invalid, then an empty string should
be used for this parameter.

Unlike FETCHOPT_MAIL_FROM(3) and FETCHOPT_MAIL_RCPT(3), the address should not
be specified within a pair of angled brackets (\<\>). However, if an empty
string is used then a pair of brackets are sent by libfetch as required by RFC
2554.

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
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_AUTH, "<secret@cave>");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
