---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAIL_RCPT_ALLOWFAILS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAIL_FROM (3)
  - FETCHOPT_MAIL_RCPT (3)
Protocol:
  - SMTP
Added-in: 8.2.0
---

# NAME

FETCHOPT_MAIL_RCPT_ALLOWFAILS - allow RCPT TO command to fail for some recipients

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAIL_RCPT_ALLOWFAILS,
                          long allow);
~~~

# DESCRIPTION

If *allow* is set to 1L, allow RCPT TO command to fail for some recipients.

When sending data to multiple recipients, by default fetch aborts the SMTP
conversation if either one of the recipients causes the RCPT TO command to
return an error.

The default behavior can be changed by setting *allow* to 1L which makes
libfetch ignore errors for individual recipients and proceed with the remaining
accepted recipients.

If all recipients trigger RCPT TO failures and this flag is specified, fetch
aborts the SMTP conversation and returns the error received from to the last
RCPT TO command.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_slist *list;
    FETCHcode res;

    /* Adding one valid and one invalid email address */
    list = fetch_slist_append(NULL, "person@example.com");
    list = fetch_slist_append(list, "invalidemailaddress");

    fetch_easy_setopt(fetch, FETCHOPT_URL, "smtp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_MAIL_RCPT_ALLOWFAILS, 1L);

    res = fetch_easy_perform(fetch);
    fetch_slist_free_all(list);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

This option was called FETCHOPT_MAIL_RCPT_ALLLOWFAILS (with three instead of
two letter L) before 8.2.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
