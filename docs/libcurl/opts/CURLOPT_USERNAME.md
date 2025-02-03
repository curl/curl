---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_USERNAME
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPAUTH (3)
  - FETCHOPT_PASSWORD (3)
  - FETCHOPT_PROXYAUTH (3)
  - FETCHOPT_USERPWD (3)
Protocol:
  - All
Added-in: 7.19.1
---

# NAME

FETCHOPT_USERNAME - username to use in authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_USERNAME,
                          char *username);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated username to use for the transfer.

FETCHOPT_USERNAME(3) sets the username to be used in protocol
authentication. You should not use this option together with the (older)
FETCHOPT_USERPWD(3) option.

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
FETCHOPT_PASSWORD(3) and FETCHOPT_LOGIN_OPTIONS(3) options.

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "clark");

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
