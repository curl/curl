---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAIL_FROM
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_AUTH (3)
  - FETCHOPT_MAIL_RCPT (3)
Protocol:
  - SMTP
Added-in: 7.20.0
---

# NAME

FETCHOPT_MAIL_FROM - SMTP sender address

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAIL_FROM, char *from);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. This should be used
to specify the sender's email address when sending SMTP mail with libfetch.

An originator email address should be specified with angled brackets (\<\>)
around it, which if not specified are added automatically.

If this parameter is not specified then an empty address is sent to the SMTP
server which might cause the email to be rejected.

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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_FROM, "president@example.com");
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
