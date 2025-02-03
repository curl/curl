---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAIL_RCPT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_AUTH (3)
  - FETCHOPT_MAIL_FROM (3)
Protocol:
  - SMTP
Added-in: 7.20.0
---

# NAME

FETCHOPT_MAIL_RCPT - list of SMTP mail recipients

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAIL_RCPT,
                          struct fetch_slist *rcpts);
~~~

# DESCRIPTION

Pass a pointer to a linked list of recipients to pass to the server in your
SMTP mail request. The linked list should be a fully valid list of
**struct fetch_slist** structs properly filled in. Use fetch_slist_append(3) to
create the list and fetch_slist_free_all(3) to clean up an entire list.

libfetch does not copy the list, it needs to be kept around until after the
transfer has completed.

When performing a mail transfer, each recipient should be specified within a
pair of angled brackets (\<\>), however, should you not use an angled bracket
as the first character libfetch assumes you provided a single email address and
encloses that address within brackets for you.

When performing an address verification (**VRFY** command), each recipient
should be specified as the username or username plus domain (as per Section
3.5 of RFC 5321).

When performing a mailing list expand (**EXPN** command), each recipient
should be specified using the mailing list name, such as `Friends` or
`London-Office`.

Using this option multiple times makes the last set list override the previous
ones. Set it to NULL to disable its use again.

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
    struct fetch_slist *list;
    list = fetch_slist_append(NULL, "root@localhost");
    list = fetch_slist_append(list, "person@example.com");
    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT, list);
    res = fetch_easy_perform(fetch);
    fetch_slist_free_all(list);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
