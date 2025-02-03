---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SASL_AUTHZID
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_USERNAME (3)
  - FETCHOPT_USERPWD (3)
Protocol:
  - IMAP
Added-in: 7.66.0
---

# NAME

FETCHOPT_SASL_AUTHZID - authorization identity (identity to act as)

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SASL_AUTHZID, char *authzid);
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
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "imap://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "Kurt");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "xipj3plmq");
    fetch_easy_setopt(fetch, FETCHOPT_SASL_AUTHZID, "Ursel");
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
